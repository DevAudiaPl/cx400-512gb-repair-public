#!/usr/bin/env python3
"""Fixed SBFQ61L3 burner loader v2: native SATA via matching SCSI generic node.

Executes vendor code in RAM. Script sends no NAND program/erase/preformat,
normal-firmware install, SMART-reset or VUC-unlock commands.
Vendor code itself has hardware access; its internal effects are not audited.
"""
import ctypes as c
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time

SECTIONS = (('iram-section0.bin', 1544421376, 131072, 'ce41164f170d8db63af060e81571bd73ea91bcfe7d8e3091a7a7c80a23389d5d'), ('iram-section1.bin', 1544323072, 32768, '19c9db0797698602bf44f9fb2723886855cdce44e02df64a6cee1972407781c3'), ('iram-section2.bin', 738328576, 32768, 'f126bbc0799e88e621f67ab28733369a033f1f880cce500ddfe9fac621007432'), ('iram-section3.bin', 1342177280, 16384, '89e700b0a2137b12e9ed2391505198bb1a6346d079869d44290d5b8cd1ff9851'), ('iram-section4.bin', 1342222336, 4096, '87f0ce414ef79d20eeb36371409fffd3738902c8019b98463f895d70747798f0'))
SRAM_SHA = 'f2545bc17088b90f3bef32d91fd235c29727dd6a86d997240865acadbac35929'
CHUNK = 65536
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

def matches_target(model, size, vendor, usb_id, has_ata_path, transport):
    if model != 'PS3111' or not 0 <= size <= 33554432:
        return False
    if transport == 'sata':
        return usb_id is None and has_ata_path and vendor == 'ATA'
    if transport == 'jm20329':
        return usb_id == ('152d', '2329')
    return False


def load_payloads(folder):
    iram=[]
    for name,address,size,expected in SECTIONS:
        data=(folder/name).read_bytes()
        if len(data)!=size or hashlib.sha256(data).hexdigest()!=expected:
            raise RuntimeError('Niepoprawny plik: '+name)
        iram.append((address,data))
    sram=(folder/'sram-xor.bin').read_bytes()
    if len(sram)!=524288 or hashlib.sha256(sram).hexdigest()!=SRAM_SHA:
        raise RuntimeError('Niepoprawny plik SRAM')
    return iram,sram


def allowed_command(opcode,feature=0,lba=0,write=None,read=0,count=0):
    if opcode==0xEC:
        return feature==0 and lba==0 and write is None and read==512 and count==0
    if opcode==0xE0:
        return feature==0 and lba==0xFAEFFE and count==0x6F and write is None and read==0
    if opcode==0x31 and read==0 and isinstance(write,bytes):
        if feature==0x24 and lba==0 and len(write)==8:
            addr,size=struct.unpack('<II',write)
            return any(addr>=start and addr+size<=start+total and size>0
                       and size%512==0 for _,start,total,_ in SECTIONS)
        if feature==0x40:
            return lba==0 and 0<len(write)<=CHUNK and len(write)%512==0
        if feature==0x0F:
            return lba==0 and write==bytes(512)
        if feature==0xBD:
            return len(write)==CHUNK and lba in tuple((i<<16)|(0x100 if i==7 else 0) for i in range(8))
    if opcode==0x21 and write is None:
        if feature in (0x30,0x13):
            return lba==0 and read==512
        if feature==0xBE:
            return read==CHUNK and lba in tuple(i<<16 for i in range(8))
    return False


def ata_identity(data):
    def words(start,count):
        raw=data[2*start:2*(start+count)]
        return b''.join(raw[i:i+2][::-1] for i in range(0,len(raw),2)).decode('ascii').strip()
    return ' '.join(words(27,20).split()),words(23,4)


def decode_system_info(data):
    if len(data)!=512 or data==bytes(512) or data==bytes([255])*512:
        raise RuntimeError('Pusta lub niepelna odpowiedz SystemInfo')
    values=SYSINFO.unpack(data)
    version_raw=values[25]
    version=b''.join(version_raw[i:i+2][::-1] for i in range(0,8,2)).decode('ascii',errors='replace').strip()
    result=dict(ce_count=values[0],channel_count=values[1],sram_log2_mib=values[2],
                ce_bitmap=hex(values[24]),firmware=version,
                pram_icode_programmed=bool(values[27]),vuc_mode=values[30],
                pages_per_block=values[3],dies_per_ce=values[4],
                blocks_per_die=values[7],blocks_per_ce=values[8],
                sectors_per_page=values[9],ce_error_bitmap=hex(values[18]|(values[31]<<32)))
    if values[1]!=2 or values[2]!=5:
        raise RuntimeError('Nieoczekiwana struktura SystemInfo: '+repr(result))
    if not result['pram_icode_programmed']:
        raise RuntimeError('SystemInfo nie potwierdza dokonczenia ICode: '+repr(result))
    return result


def run_loader(command,emit,iram,sram,pause=time.sleep):
    def send(opcode,**kwargs):
        if not allowed_command(opcode,**kwargs):
            raise RuntimeError('Odmowa polecenia spoza listy testu burnera')
        return command(opcode,**kwargs)
    def identify(stage,expected):
        model,firmware=ata_identity(send(0xEC,read=512))
        emit(stage=stage,ata_model=model,ata_firmware=firmware)
        if (model,firmware)!=expected:
            raise RuntimeError('Nieoczekiwana identyfikacja ATA; odmowa dalszych zapisow')
    def vuc(feature,write=None,read=0,lba=0):
        send(0xE0,lba=0xFAEFFE,count=0x6F)
        return send(0x21 if read else 0x31,feature=feature,write=write,read=read,lba=lba)

    identify('initial',('PS3111','SBRM02.0'))
    for index,(address,data) in enumerate(iram):
        for pos in range(0,len(data),CHUNK):
            part=data[pos:pos+CHUNK]
            vuc(0x24,write=struct.pack('<II',address+pos,len(part)))
            vuc(0x40,write=part)
        vuc(0x24,write=struct.pack('<II',address,len(data)))
        marker=struct.unpack_from('<I',vuc(0x30,read=512),8)[0]
        emit(stage='iram_crc',section=index,address=hex(address),bytes=len(data),crc_marker=hex(marker))
        if marker!=0x55AA55AA:
            raise RuntimeError('Blad CRC IRAM; skok do kodu NIE zostal wyslany')
    emit(stage='jump',note='Executing verified vendor IRAM code')
    vuc(0x0F,write=bytes(512))
    pause(1)
    identify('minimal_burner',('SATABURN SB','SBBQ61L3'))
    for index,pos in enumerate(range(0,len(sram),CHUNK)):
        piece=sram[pos:pos+CHUNK]
        final=pos+len(piece)==len(sram)
        vuc(0xBD,write=piece,lba=(index<<16)|(0x100 if final else 0))
        received=vuc(0xBE,read=len(piece),lba=index<<16)
        if received!=piece:
            raise RuntimeError('Odczyt SRAM niezgodny w bloku '+str(index))
        emit(stage='sram_verified',chunk=index,loaded=pos+len(piece),total=len(sram),final=final)
    identify('full_burner',('SATABURN SB','SBBQ61L3'))
    raw_info=vuc(0x13,read=512)
    info=decode_system_info(raw_info)
    emit(stage='system_info',**info)
    emit(result='BURNER FULLY LOADED; SRAM VERIFIED; ICODE CONFIRMED',
         note='SSD not repaired yet. No NAND write/erase/install commands sent by this script.')
    return raw_info


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


def main():
    if not sys.platform.startswith('linux'):
        raise RuntimeError('Ten loader wymaga Linuksa')
    if os.geteuid()!=0:
        raise RuntimeError('Uruchom: sudo python3 cx400-burner.py')
    if c.sizeof(SgIoHdr)!=(88 if c.sizeof(c.c_void_p)==8 else 64) or SYSINFO.size!=512:
        raise RuntimeError('Niepoprawna struktura interfejsu')
    iram,sram=load_payloads(Path(__file__).resolve().parent)
    stamp=datetime.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')
    report=Path.cwd()/('cx400-burner-result-'+stamp+'.txt')
    with report.open('w',encoding='utf-8',buffering=1) as log:
        def emit(**obj):
            obj={'time':datetime.datetime.now().astimezone().isoformat(),**obj}
            line=json.dumps(obj,ensure_ascii=True)
            print(line,flush=True); log.write(line+'\n')
        emit(started=datetime.datetime.now().astimezone().isoformat(),kernel=os.uname().release,
             report=str(report),loader='v2-sg',mode='VENDOR BURNER EXECUTION IN RAM; NO NAND PROGRAM/ERASE COMMANDS SENT')
        candidates=[]
        for block in Path('/sys/class/block').iterdir():
            if (block/'partition').exists():
                continue
            try:
                model=(block/'device/model').read_text().strip()
                size=int((block/'size').read_text())*512
                if model!='PS3111' or not 0<=size<=33554432:
                    continue
                vendor=(block/'device/vendor').read_text().strip()
                path=(block/'device').resolve(strict=True)
                ancestors=(path,)+tuple(path.parents)
                has_ata=any(p.name.startswith('ata') and p.name[3:].isdigit() for p in ancestors)
                usb=any((p/'idVendor').exists() for p in ancestors)
                if matches_target(model,size,vendor,('usb','usb') if usb else None,has_ata,'sata'):
                    candidates.append((Path('/dev')/block.name,size,str(path)))
            except (OSError,ValueError):
                continue
        if len(candidates)!=1:
            emit(error='Wymagany dokladnie jeden PS3111 do32MiB na natywnym SATA',
                 candidates=[str(x[0]) for x in candidates])
            return 2
        device,size,path=candidates[0]
        emit(device=str(device),capacity=size,connection_path=path,transport='sata')
        try:
            sg_device=find_sg_device(Path(path))
            if not stat.S_ISCHR(sg_device.stat().st_mode):
                raise RuntimeError('Wybrane sg nie jest urzadzeniem znakowym; odmowa')
            emit(stage='opening_sg',block_device=str(device),sg_device=str(sg_device))
            fd=os.open(str(sg_device),os.O_RDWR|os.O_CLOEXEC)
            emit(stage='sg_opened',sg_device=str(sg_device))
        except Exception as exc:
            emit(error=str(exc),result='STOPPED BEFORE SG_IO; BLOCK DEVICE NOT OPENED')
            return 2
        libc=c.CDLL(None,use_errno=True)
        libc.ioctl.argtypes=[c.c_int,c.c_ulong,c.c_void_p]
        libc.ioctl.restype=c.c_int
        try:
            def command(opcode,feature=0,lba=0,write=None,read=0,count=0):
                if not allowed_command(opcode,feature,lba,write,read,count):
                    raise RuntimeError('Odmowa polecenia spoza listy loadera')
                outgoing=bytes(write) if write is not None else None
                if outgoing is not None:
                    outgoing+=bytes(-len(outgoing)%512)
                length=len(outgoing) if outgoing is not None else read
                if length>CHUNK:
                    raise RuntimeError('Transfer przekracza64KiB')
                direction=-2 if outgoing is not None else -3 if read else -1
                protocol=5 if outgoing is not None else 4 if read else 3
                flags=6 if outgoing is not None else 14 if read else 0
                sectors=length//512 if length else count
                cdb=bytes([0xA1,protocol<<1,flags,feature,sectors,lba&255,(lba>>8)&255,(lba>>16)&255,0xA0,opcode,0,0])
                cmdbuf=c.create_string_buffer(cdb,len(cdb))
                databuf=c.create_string_buffer(max(length,1)); sense=c.create_string_buffer(64)
                if outgoing is not None:
                    c.memmove(databuf,outgoing,length)
                hdr=SgIoHdr(); hdr.interface_id=ord('S'); hdr.dxfer_direction=direction
                hdr.cmd_len=len(cdb); hdr.mx_sb_len=len(sense); hdr.dxfer_len=length
                hdr.dxferp=c.addressof(databuf) if length else None
                hdr.cmdp=c.addressof(cmdbuf); hdr.sbp=c.addressof(sense); hdr.timeout=3000
                started=time.monotonic()
                result=libc.ioctl(fd,0x2285,c.byref(hdr))
                err=c.get_errno() if result<0 else 0
                if result<0 or hdr.status or hdr.host_status or hdr.driver_status or hdr.resid:
                    emit(failed_opcode=hex(opcode),feature=hex(feature),lba=hex(lba),bytes=length,
                         errno=err,scsi_status=hdr.status,host_status=hdr.host_status,driver_status=hdr.driver_status,
                         residual=hdr.resid,sense=sense.raw[:hdr.sb_len_wr].hex(),seconds=round(time.monotonic()-started,3))
                    raise RuntimeError('SG_IO nie powiodlo sie; test zatrzymany bez ponowien')
                return databuf.raw[:read] if read else None
            raw_info=run_loader(command,emit,iram,sram)
            info_path=Path.cwd()/('cx400-system-info-'+stamp+'.bin')
            info_path.write_bytes(raw_info)
            emit(system_info_file=str(info_path))
            return 0
        except Exception as exc:
            emit(error=str(exc),result='STOPPED WITHOUT RETRY')
            return 1
        finally:
            os.close(fd)


if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('STOP: '+str(exc),file=sys.stderr)
        sys.exit(2)
