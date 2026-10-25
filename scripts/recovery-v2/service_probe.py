#!/usr/bin/env python3
"""Read fixed NAND service metadata using checked ECC/pSLC read commands.
No NAND program, erase, InfoBlock write or firmware installation.
"""
import ctypes as c
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time
import zipfile
from link_guard import require_link
from trace_capture import Capture

SYSINFO = struct.Struct('<Bx2BHB3x2B4xL8xL8xL28x2BxB124xB3xH2x3L16x2LB2xB2H76xQ8x8s9s2xB54xH4x2sB35xL46x')

class SgIoHdr(c.Structure):
    _fields_ = [
        ('interface_id', c.c_int), ('dxfer_direction', c.c_int),
        ('cmd_len', c.c_ubyte), ('mx_sb_len', c.c_ubyte),
        ('iovec_count', c.c_ushort), ('dxfer_len', c.c_uint),
        ('dxferp', c.c_void_p), ('cmdp', c.c_void_p), ('sbp', c.c_void_p),
        ('timeout', c.c_uint), ('flags', c.c_uint), ('pack_id', c.c_int),
        ('usr_ptr', c.c_void_p), ('status', c.c_ubyte),
        ('masked_status', c.c_ubyte), ('msg_status', c.c_ubyte),
        ('sb_len_wr', c.c_ubyte), ('host_status', c.c_ushort),
        ('driver_status', c.c_ushort), ('resid', c.c_int),
        ('duration', c.c_uint), ('info', c.c_uint),
    ]


def find_sg_device(sys_device,sg_class=Path('/sys/class/scsi_generic'),dev_root=Path('/dev')):
    if not sg_class.is_dir():
        raise RuntimeError('Brak interfejsu sg. Wykonaj sudo modprobe sg i uruchom loader ponownie.')
    matches=[]
    for entry in sg_class.iterdir():
        if not entry.name.startswith('sg') or not entry.name[2:].isdigit():
            continue
        try:
            if (entry/'device').resolve(strict=True)==sys_device:
                matches.append(dev_root/entry.name)
        except OSError:
            continue
    if len(matches)!=1:
        raise RuntimeError('Brak jednoznacznego sg dla badanego SSD; bez otwierania urzadzenia blokowego. Wykonaj sudo modprobe sg.')
    return matches[0]


def ata_identity(data):
    def words(start,count):
        raw=data[2*start:2*(start+count)]
        return b''.join(raw[i:i+2][::-1] for i in range(0,len(raw),2)).decode('ascii').strip()
    return ' '.join(words(27,20).split()),words(23,4)


def parse_info(data):
    if len(data)!=512: raise RuntimeError('Niepelny SystemInfo')
    v=SYSINFO.unpack(data)
    raw=v[25]
    fw=b''.join(raw[i:i+2][::-1] for i in range(0,8,2)).decode('ascii').strip()
    result=dict(ce_count=v[0],channel_count=v[1],sram_log2_mib=v[2],
                ce_bitmap=hex(v[24]),firmware=fw,pram_icode_programmed=bool(v[27]),
                vuc_key=int.from_bytes(v[29],'big'),vuc_mode=v[30],
                pages_per_block=v[3],blocks_per_die=v[7],blocks_per_ce=v[8],
                sectors_per_page=v[9],ce_error_bitmap=hex(v[18]|(v[31]<<32)))
    if (v[0],v[1],v[2],v[24],fw,bool(v[27]))!=(8,2,5,0x0f0f,'SBBQ61L3',True):
        raise RuntimeError('Nieoczekiwany burner lub geometria; odmowa dalszych polecen: '+repr(result))
    return result


def word_string(raw):
    return b''.join(raw[i:i+2][::-1] for i in range(0,len(raw),2)).decode('ascii',errors='replace').strip(' \x00')


def crc32(data,seed):
    if len(data)%4: raise ValueError('CRC requires words')
    state=seed
    for offset in range(0,len(data),4):
        state^=int.from_bytes(data[offset:offset+4],'little')
        for _ in range(32):
            feedback=state&0x80000000
            state=(state<<1)&0xffffffff
            if feedback: state^=0x04c11db7
    return state


def matches_inspect_target(model,size,vendor,has_ata,usb):
    if vendor!='ATA' or not has_ata or usb: return False
    model=' '.join(model.split())
    if model=='PS3111': return 0<=size<=33554432
    if model=='SATABURN SB': return 0<=size<=33554432 or size==268435455*512
    return False


def parse_ata_sense(data):
    if len(data)<8: return {}
    response=data[0]&0x7f
    if response in (0x70,0x71):
        if len(data)<18: return {}
        return dict(format='fixed',sense_key=data[2]&15,asc=data[12],ascq=data[13],
                    error=data[3],status=data[4],device=data[5],count=data[6])
    if response in (0x72,0x73):
        result=dict(format='descriptor',sense_key=data[1]&15,asc=data[2],ascq=data[3])
        end=min(len(data),8+data[7]);pos=8
        while pos+2<=end:
            total=2+data[pos+1]
            if pos+total>end: break
            if data[pos]==9 and total>=14:
                desc=data[pos:pos+total]
                result.update(error=desc[3],count=desc[5],device=desc[12],status=desc[13])
                return result
            pos+=total
        return result
    return {}


def informational_ata_sense(data):
    a=parse_ata_sense(data)
    return (a.get('sense_key') in (0,1) and a.get('asc')==0 and a.get('ascq')==0x1d
            and a.get('error')==0 and (a.get('status',0)&0xe9)==0x40)


def select_device():
    candidates=[]
    for block in Path('/sys/class/block').iterdir():
        if (block/'partition').exists(): continue
        try:
            model=(block/'device/model').read_text().strip()
            size=int((block/'size').read_text())*512
            if ' '.join(model.split()) not in ('PS3111','SATABURN SB'): continue
            vendor=(block/'device/vendor').read_text().strip()
            path=(block/'device').resolve(strict=True)
            ancestors=(path,)+tuple(path.parents)
            has_ata=any(p.name.startswith('ata') and p.name[3:].isdigit() for p in ancestors)
            usb=any((p/'idVendor').exists() for p in ancestors)
            if matches_inspect_target(model,size,vendor,has_ata,usb):
                candidates.append((Path('/dev')/block.name,size,path,model))
        except (OSError,ValueError): continue
    if len(candidates)!=1: raise RuntimeError('Wymagany dokladnie jeden PS3111-ROM lub SATABURN z pojemnoscia serwisowa na SATA')
    block,size,path,cached_model=candidates[0]
    sg=find_sg_device(path)
    if not stat.S_ISCHR(sg.stat().st_mode): raise RuntimeError('Wybrane sg nie jest urzadzeniem znakowym')
    return block,size,path,sg,cached_model


SERVICE_BLOCKS = tuple(range(200))
NAND_LBA = 0x18001
NAND_READ_BYTES = 16896

def nand_parameter(ce,block,page=0):
    if ce not in (0,8) or block not in SERVICE_BLOCKS or page!=0:
        raise ValueError('Adres poza CE0/8, blok0..199, strona0')
    return struct.pack('<20xBxHH',ce,block,page).ljust(512,b'\0')

def allowed_command(opcode,feature=0,lba=0,write=None,read=0,count=0):
    if opcode==0xec:
        return feature==lba==count==0 and write is None and read==512
    if opcode==0xe0:
        return feature==0 and lba==0xfaeffe and write is None and read==0 and count==0x6f
    if count!=0:return False
    if opcode==0x31 and lba==0 and read==0 and isinstance(write,bytes):
        if feature==0x24 and len(write)==512:
            ce=write[20];block,page=struct.unpack_from('<HH',write,22)
            return ce in (0,8) and block in SERVICE_BLOCKS and page==0 and write==nand_parameter(ce,block,page)
        if feature in (0xc4,0xc7):return write==bytes(512)
        if feature==0xc6:return len(write)==512
    if opcode==0x21 and write is None:
        return ((feature in (0x13,0xc5) and read==512 and lba==0)
                or (feature==0x10 and read==NAND_READ_BYTES and lba==NAND_LBA))
    return False

class AtaDeviceError(RuntimeError):
    """Completed command with real ATA ERR, but no transport failure."""


def make_cdb(opcode, feature, lba, length, outgoing, count):
    protocol = 5 if outgoing else 4 if length else 3
    flags = 6 if outgoing else 14 if length else 0
    if opcode == 0x21 and feature == 0x10:
        flags |= 0x20
    sectors = length // 512 if length else count
    return bytes([0xA1, protocol << 1, flags, feature, sectors,
                  lba & 255, (lba >> 8) & 255, (lba >> 16) & 255,
                  0xAF if opcode == 0xE0 else 0xA0, opcode, 0, 0])


def is_completed_ata_error(rc, status, host, driver, residual, length, sense):
    a = parse_ata_sense(sense)
    return (rc >= 0 and status == 2 and host == 0 and driver in (0, 8)
            and 0 <= residual <= length and a.get('error', 0) != 0
            and (a.get('status', 0) & 0xE9) == 0x41)


def header_fields(raw):
    if len(raw) != 4096:
        raise ValueError('Niepelny naglowek')
    expected = int.from_bytes(raw[-4:], 'little')
    actual = crc32(raw[:-8], 0x31113111)
    return dict(magic=raw[:2].hex(), magic_valid=raw[:2] == b'ID',
                stored_crc=hex(expected), computed_crc=hex(actual),
                crc_valid=actual == expected,
                valid=raw[:2] == b'ID' and actual == expected,
                write_sequence_raw=raw[2],
                copy_blocks_raw=list(struct.unpack_from('<4H', raw, 4)),
                pages_per_block_raw=struct.unpack_from('<H', raw, 12)[0])


def check_system(raw, allow_engineering=False):
    info = parse_info(raw)
    if (info['vuc_key'], info['pages_per_block'], info['blocks_per_die'],
        info['blocks_per_ce'], info['sectors_per_page']) != (4, 768, 2956, 5912, 32):
        raise RuntimeError('Niezgodny klucz VUC lub geometria NAND: ' + repr(info))
    accepted_modes = (2, 3) if allow_engineering else (3,)
    if info['vuc_mode'] not in accepted_modes:
        raise RuntimeError('Stan VUC ulegl zmianie: ' + repr(info))
    return info








def derive_seed(data):
    folded=bytearray(32)
    for i,value in enumerate(data): folded[i%32]^=value
    return int.from_bytes(folded[:4],'little')

def cipher(data,seed):
    def reverse(x): return int(format(x&65535,'016b')[::-1],2)
    def advance(x):
        for _ in range(16): x=((x<<1)^(0x8005 if x&0x8000 else 0))&65535
        return x
    output=bytearray()
    for offset in range(0,len(data),512):
        key=(seed+offset//512)&0xffffffff
        state=advance(0x1234^reverse(key&65535))
        state=advance(state^reverse(key>>16))
        stream=bytearray()
        for _ in range(16):
            r=reverse(state); n=state^65535; nr=r^65535
            words=(((state<<4)&0xff00)|((state>>2)&0xff),
                   ((nr<<10)&0xf000)|((state>>3)&0xfff),
                   ((r<<4)&0xfff0)|((n>>8)&0xf),
                   ((state<<3)&0xfff0)|((r>>2)&0xf),r,
                   ((n<<8)|(state>>8))&65535,((r<<4)&0xf000)|(n&0xfff),state,
                   ((r<<1)&0xfff0)|((state>>11)&0xf),nr,
                   ((state<<8)|(state>>8))&65535,((r<<8)|(r>>8))&65535,n,r,
                   ((state<<2)&0xfff0)|((r>>1)&0xf),state)
            stream+=struct.pack('<16H',*words)
            for word in words: state=advance(state^reverse(word))
        piece=data[offset:offset+512]
        output.extend(a^b for a,b in zip(piece,stream))
    return bytes(output)

def run_probe(command, emit, save):
    def vuc(feature, read=0, write=None, lba=0, label=None):
        command(0xE0, lba=0xFAEFFE, count=0x6F)
        return command(0x21 if read else 0x31, feature=feature, lba=lba,
                       read=read, write=write, label=label)
    def guard(label, allow_engineering=False):
        identity = command(0xEC, read=512, label=label+'-identify')
        save('identity-'+label+'.bin', identity)
        model, firmware = ata_identity(identity)
        if (model, firmware) != ('SATABURN SB', 'SBBQ61L3'):
            raise RuntimeError('Wymagany SATABURN SB/SBBQ61L3')
        raw = vuc(0x13, read=512, label=label+'-system-info')
        save('system-info-'+label+'.bin', raw)
        info = check_system(raw, allow_engineering=allow_engineering)
        emit(stage=label, ata_model=model, ata_firmware=firmware, **info)
        return info
    initial = guard('initial', allow_engineering=True)
    if initial['vuc_mode'] == 2:
        vuc(0xc7, write=bytes(512), label='auth-reset')
        if guard('auth-reset', allow_engineering=True)['vuc_mode'] != 2:
            raise RuntimeError('Nieoczekiwany stan po resecie autoryzacji')
        vuc(0xc4, write=bytes(512), label='auth-start')
        challenge = vuc(0xc5, read=512, label='auth-challenge')
        save('auth-challenge.bin', challenge)
        first = cipher(challenge, 1364702134)
        answer = cipher(first, 1364702134 ^ derive_seed(first))
        vuc(0xc6, write=answer, label='auth-answer')
        guard('after-auth')
    else:
        emit(stage='authorization', result='ALREADY UNLOCKED')
    emit(stage='service_read_plan',ce_addresses=[0,8],blocks=[0,199],page=0,
         page_bytes=NAND_READ_BYTES,total_unique_pages=400,
         note='Physical page0 with ECC/pSLC; compare metadata to preserved normal firmware lookup; no NAND writes')
    records=[];done=set();consecutive_errors=0
    def read_page(ce,block):
        nonlocal consecutive_errors
        guard('ce%02d-block%03d'%(ce,block))
        label='service-ce%02d-block%03d-page000'%(ce,block)
        vuc(0x24,write=nand_parameter(ce,block),label=label+'-parameter')
        try:
            raw=vuc(0x10,read=NAND_READ_BYTES,lba=NAND_LBA,label=label)
        except AtaDeviceError as exc:
            records.append(dict(ce=ce,block=block,read_ok=False,error=str(exc)))
            emit(stage='service_page_device_error',**records[-1])
            consecutive_errors+=1
            if consecutive_errors>=4:
                raise RuntimeError('Cztery kolejne bledy ATA stron; STOP, bez ponowien i bez diagnozy pustej NAND')
            return None
        if len(raw)!=NAND_READ_BYTES:raise RuntimeError('Niepelna strona NAND')
        consecutive_errors=0
        save(label+'.bin',raw)
        words=list(struct.unpack_from('<8I',raw,16384))
        record=dict(ce=ce,block=block,read_ok=True,oob_words=[hex(w) for w in words],
                    data_prefix=raw[:32].hex(),metadata_signature=hex(words[0]),
                    phison_marker_offsets=[i for i in range(0,16384-5) if raw[i:i+6]==b'PhIsOn'])
        records.append(record);done.add((ce,block));emit(stage='service_page',**record)
        return raw
    # Known good NAND page confirms parameters/transport before interpreting OOB.
    raw=read_page(0,0)
    if raw is None or hashlib.sha256(raw[:4096]).hexdigest()!='a2ce395fb3b48113f1e06618eda0545e282270107cb6a17235afcb6f0a581800':
        raise RuntimeError('Kontrola znanego naglowka NAND nie przeszla; bez skanowania')
    # The actual normal firmware table points to block7 in both channels.
    controls=[]
    for ce in (0,8):
        raw=read_page(ce,7)
        controls.append(raw is not None and struct.unpack_from('<I',raw,16384)[0]==0x3fb10200)
    save('service-page-index.json',json.dumps(records,indent=2).encode())
    if not all(controls):
        raise RuntimeError('Zachowano blok7, ale format OOB nie potwierdza 3fb10200; STOP przed szerszym skanem')
    emit(stage='metadata_positive_controls',matched=True,
         note='Both block7 OOB markers match classifier in SBFM61.3; scan remaining fixed first pages')
    for ce in (0,8):
        for block in SERVICE_BLOCKS:
            if (ce,block) in done:continue
            try:
                read_page(ce,block)
            finally:
                save('service-page-index.json',json.dumps(records,indent=2).encode())
    guard('final')
    emit(result='SERVICE METADATA READ COMPLETED',unique_successful_pages=len(done),
         page_errors=sum(not x['read_ok'] for x in records),
         note='A failed page is not an erased page; no NAND programming/erase, no InfoBlock writes')



def main():
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('Wymagany Linux; sudo python3 service_probe.py')
    if c.sizeof(SgIoHdr) != (88 if c.sizeof(c.c_void_p) == 8 else 64) or SYSINFO.size != 512:
        raise RuntimeError('Niepoprawny rozmiar interfejsu')
    stamp = datetime.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')
    folder = Path.cwd() / ('cx400-service-read-stage-' + stamp)
    folder.mkdir()
    status = 1
    with (folder / 'report.txt').open('w', encoding='utf-8', buffering=1) as log:
        def emit(**obj):
            obj = {'time': datetime.datetime.now().astimezone().isoformat(), **obj}
            line = json.dumps(obj, ensure_ascii=True)
            print(line, flush=True)
            log.write(line + '\n')

        def save(name, data):
            (folder / name).write_bytes(data)
            emit(saved=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

        def capture_dmesg(name):
            capture = subprocess.run(['dmesg', '-T'], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=10)
            (folder / name).write_bytes(capture.stdout)
            emit(dmesg_file=name, exit_code=capture.returncode)
            if capture.stderr:
                (folder / (name + '.stderr')).write_bytes(capture.stderr)

        fd = None
        trace_capture = None
        try:
            emit(mode='SERVICE METADATA READ; FIXED PAGE0 OF BLOCKS0..199 ON CE0/8; SATA1.5 REQUIRED', kernel=os.uname().release)
            capture_dmesg('dmesg-before.txt')
            block, size, path, sg, cached_model = select_device()
            emit(block_device=str(block), capacity=size, cached_model=cached_model,
                 connection_path=str(path), sg_device=str(sg))
            link = require_link(path,Path('/proc/cmdline').read_text())
            emit(stage='link_guard',**link)
            trace_capture = Capture(path,folder,emit)
            trace_capture.start()
            (trace_capture.instance/'buffer_size_kb').write_text('8192\n')
            fd = os.open(str(sg), os.O_RDWR | os.O_CLOEXEC)
            libc = c.CDLL(None, use_errno=True)
            libc.ioctl.argtypes = [c.c_int, c.c_ulong, c.c_void_p]
            libc.ioctl.restype = c.c_int
            pending_ce = None

            def command(opcode, feature=0, lba=0, write=None, read=0, count=0, label=None):
                nonlocal pending_ce
                if not allowed_command(opcode, feature, lba, write, read, count):
                    raise RuntimeError('Niedozwolona komenda')
                if opcode == 0x21 and feature == 0x10 and pending_ce is None:
                    raise RuntimeError('Odczyt NAND bez ustalonych parametrow')
                outgoing = bytes(write) if write is not None else None
                length = len(outgoing) if outgoing is not None else read
                if length > 65536 or length % 512:
                    raise RuntimeError('Niepoprawny transfer')
                registers = opcode == 0x21 and feature in (0x10,0x31)
                direction = -2 if outgoing is not None else -3 if read else -1
                cdb = make_cdb(opcode, feature, lba, length, outgoing is not None, count)
                if opcode == 0xE0:
                    emit(stage='ap_key_request', cdb=cdb.hex(), ata_device=hex(cdb[8]))
                cmdbuf = c.create_string_buffer(cdb, len(cdb))
                databuf = c.create_string_buffer(max(length, 1))
                sensebuf = c.create_string_buffer(64)
                if outgoing is not None:
                    c.memmove(databuf, outgoing, length)
                h = SgIoHdr()
                h.interface_id = ord('S')
                h.dxfer_direction = direction
                h.cmd_len = len(cdb)
                h.mx_sb_len = len(sensebuf)
                h.dxfer_len = length
                h.dxferp = c.addressof(databuf) if length else None
                h.cmdp = c.addressof(cmdbuf)
                h.sbp = c.addressof(sensebuf)
                h.timeout = 30000
                if opcode == 0x21 and feature == 0x10:
                    pending_ce = None  # consume parameter: no implicit reuse
                started = time.monotonic()
                rc = libc.ioctl(fd, 0x2285, c.byref(h))
                err = c.get_errno() if rc < 0 else 0
                sense = sensebuf.raw[:h.sb_len_wr]
                informational = (registers and rc >= 0 and h.status == 2 and h.host_status == 0
                                 and h.driver_status in (0, 8) and h.resid == 0
                                 and informational_ata_sense(sense))
                if registers:
                    emit(stage='ata_result', operation=label, cdb=cdb.hex(),
                         scsi_status=h.status, host_status=h.host_status, driver_status=h.driver_status,
                         residual=h.resid, sense=sense.hex(), ata_registers=parse_ata_sense(sense),
                         informational_completion=informational)
                if (rc < 0 or h.status or h.host_status or h.driver_status or h.resid) and not informational:
                    if read and label:
                        save(label + '-UNTRUSTED.bin', databuf.raw[:read])
                    emit(failed_opcode=hex(opcode), feature=hex(feature), lba=hex(lba), bytes=length,
                         cdb=cdb.hex(), operation=label, ata_registers=parse_ata_sense(sense),
                         errno=err, scsi_status=h.status, host_status=h.host_status,
                         driver_status=h.driver_status, residual=h.resid, sense=sense.hex(),
                         seconds=round(time.monotonic() - started, 3))
                    if registers and is_completed_ata_error(rc, h.status, h.host_status,
                                                           h.driver_status, h.resid, length, sense):
                        raise AtaDeviceError(str(parse_ata_sense(sense)))
                    raise RuntimeError('Blad transportu/komendy; koniec bez ponowien')
                if opcode == 0x31 and feature == 0x24:
                    pending_ce = (outgoing[20],) + struct.unpack_from('<HH',outgoing,22)
                return databuf.raw[:read] if read else None

            run_probe(command, emit, save)
            status = 0  # diagnostic completed; detailed fields report each device error
        except Exception as exc:
            emit(error=str(exc), result='STOPPED WITHOUT RETRY')
            if fd is not None:
                try:
                    raw = command(0xEC, read=512)
                    save('identity-after-stop.bin', raw)
                    model, firmware = ata_identity(raw)
                    emit(stage='identity_after_stop', ata_model=model, ata_firmware=firmware)
                    if (model, firmware) == ('SATABURN SB', 'SBBQ61L3'):
                        command(0xE0, lba=0xFAEFFE, count=0x6F)
                        raw = command(0x21, feature=0x13, read=512)
                        save('system-info-after-stop.bin', raw)
                        emit(stage='system_info_after_stop', **parse_info(raw))
                except Exception as snapshot_error:
                    emit(snapshot_error=str(snapshot_error))
        finally:
            if fd is not None:
                os.close(fd)
            if trace_capture is not None:
                trace_capture.close()
            try:
                capture_dmesg('dmesg.txt')
            except Exception as exc:
                emit(dmesg_error=str(exc))
    archive = folder.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.iterdir()):
            if p.is_file():
                z.write(p, arcname=p.name)
    print('RESULT ZIP: ' + str(archive), flush=True)
    return status


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(2)
