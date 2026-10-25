#!/usr/bin/env python3
"""Fixed CX400512/BiCS3 recovery through native Linux SG_IO. No vendor EXE.

Run --repair for the authorized destructive attempt. Default is precheck.
On any transport, device, trace or content error, stop without retry/reset.
"""
import argparse
import ctypes as c
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
import zipfile

PACKAGE_VERSION='linux-recovery-2'
ASSETS_SHA256='8ab703418cb74103cbb77495d69ea3f90c40499bad6f40fd7a048bde126b0168'
CES=(0,1,2,3,8,9,10,11)
FID=bytes.fromhex('98 3e 99 b3 7a 72 08 06')
CONTROLS={0x5c0e0400:0x00000b06,0x60000400:0x5c0e1e14}
STATE_ADDRESSES=tuple(CONTROLS)+(0x5c0cda98,0x5c0cdafc,0x5c0cf1d0,
                               0x5c0cf1d4,0x5c0cdd74,0x5c0cf1dc)
SEED_ADDRESSES=(0x5c0cdc38,0x5c0cdc3c,0x5c0cdc40,0x5c0cdc44)+tuple(range(0x5c0cef70,0x5c0cefd0,4))
WORDS=frozenset(STATE_ADDRESSES+SEED_ADDRESSES)
ERASE_TIMEOUT=960
FORMAT_TIMEOUT=1280

def sha(data):return hashlib.sha256(data).hexdigest()
def need(condition,message):
    if not condition:raise RuntimeError(message)

def parse_sense(raw):
    if len(raw)<8:return {}
    form=raw[0]&127
    if form in (0x70,0x71):
        if len(raw)<18:return {}
        result=dict(format='fixed',sense_key=raw[2]&15,asc=raw[12],ascq=raw[13])
        # libata-scsi.c ata_scsi_set_passthru_sense_fields fixed format.
        if raw[0]&128:
            result.update(error=raw[3],status=raw[4],device=raw[5],count=raw[6],
                          lbal=raw[9],lbam=raw[10],lbah=raw[11])
        return result
    if form not in (0x72,0x73):return {}
    result=dict(format='descriptor',sense_key=raw[1]&15,asc=raw[2],ascq=raw[3])
    pos=8;end=min(len(raw),8+raw[7])
    while pos+2<=end:
        size=raw[pos+1]+2
        if size<2 or pos+size>end:return result
        d=raw[pos:pos+size]
        if d[0]==9 and size>=14:
            result.update(error=d[3],count=d[5],lbal=d[7],lbam=d[9],lbah=d[11],device=d[12],status=d[13])
            return result
        pos+=size
    return result

def completed_ok(rc,scsi,host,driver,residual,ata):
    return (rc>=0 and scsi in (0,2) and host==0 and driver in (0,8) and residual==0
            and ata.get('sense_key') in (0,1) and ata.get('asc')==0
            and ata.get('ascq') in (0,0x1d) and ata.get('error')==0
            and (ata.get('status',0)&0xe9)==0x40)

def make_cdb(opcode,feature,lba,length,outgoing,count=0):
    need(0<=lba<=0xffffff and 0<=feature<=255,'Taskfile range')
    need(length%512==0 and length<=65536,'PIO length')
    protocol=5 if outgoing else 4 if length else 3
    flags=0x20|(6 if outgoing else 14 if length else 0) # CK_COND on every command.
    sectors=length//512 if length else count
    return bytes((0xa1,protocol<<1,flags,feature,sectors,lba&255,(lba>>8)&255,
                  (lba>>16)&255,0xaf if opcode==0xe0 else 0xa0,opcode,0,0))

def trace_clean(text):
    names=('ata_qc_complete_failed:','ata_eh_link_autopsy:',
           'ata_eh_link_autopsy_qc:','ata_link_hardreset_begin:',
           'ata_link_softreset_begin:')
    return not any(not line.lstrip().startswith('#') and any(n in line for n in names)
                   for line in text.splitlines())

class Assets:
    def __init__(self,root):
        raw=(root/'assets.json').read_bytes();need(sha(raw)==ASSETS_SHA256,'Niezgodny manifest assets.json')
        meta=json.loads(raw);self.root=root
        for name,info in meta['files'].items():
            data=(root/name).read_bytes()
            need(len(data)==info['size'] and sha(data)==info['sha256'],'Niezgodny plik: '+name)
        self.normal=(root/'normal-SBFM61.3.bin').read_bytes()
        need(len(self.normal)==786432,'Nieprawidlowy rozmiar normal firmware')
        self.seed=self.normal[:16384];self.code=self.normal[16384:]
        self.layout=json.loads((root/'normal-layout.json').read_bytes())
        self.expected={0x5c0cdc38:0x71494f27,0x5c0cdc3c:0x71494f27,0x5c0cdc40:0}
        for i in range(8):
            self.expected[0x5c0cef70+i*4]=struct.unpack_from('<I',self.seed,i*8)[0]
            self.expected[0x5c0cef90+i*4]=struct.unpack_from('<I',self.seed,64+i*8)[0]
            self.expected[0x5c0cefb0+i*4]=struct.unpack_from('<I',self.seed,4+i*8)[0]
        self.template=(root/'infoblock-template.bin').read_bytes()
        self.smart=(root/'smart-template.bin').read_bytes()
        self.preformat=None

    def build_preformat(self,serial):
        need(len(serial)==20 and serial.isascii() and serial.isalnum(),'SN wymaga20 znakow ASCII')
        ib=bytearray(self.template)
        def swapped(s,size):
            b=s.encode('ascii').ljust(size,b' ')
            return b''.join(b[i:i+2][::-1] for i in range(0,size,2))
        ib[0x12:0x26]=swapped(serial,20)
        ib[0x26:0x4e]=swapped('SATA SSD',40)
        ib[0x57]=0x19;ib[0x62]=3
        struct.pack_into('<H',ib,0x6b,0x703)
        struct.pack_into('<I',ib,0x1f5,0x014e5744);ib[0x1f9]=0
        self.preformat=bytes(ib)+self.smart
        need(len(self.preformat)==1024 and self.preformat[:6]==b'PhIsOn','PreFormat packet size/magic')
        return self.preformat

class Reply:
    def __init__(self,data=b'',ata=None):self.data=data;self.ata=ata or {}

class Gate:
    """Lowest I/O boundary. No generic ATA/NAND write interface."""
    def __init__(self,assets,loader):
        self.assets=assets;self.loader=loader;self.phase='read';self.next_chunk=0
        self.verify_header=False;self.verify_offset=0;self.pending_sram=None
        self.auth_answer=None;self.failed=False;self.pending_word=None

    def allow(self,opcode,feature,lba,write,read,count):
        need(not self.failed,'Port zatrzymany po bledzie; bez dalszych komend')
        if self.phase=='loader':
            need(self.loader.allowed_command(opcode,feature,lba,write,read,count),'Komenda poza loaderem')
            return
        if opcode==0xec and feature==lba==count==0 and write is None and read==512:return
        if opcode==0xe0 and feature==0 and lba==0xfaeffe and count==0x6f and write is None and read==0:return
        need(count==0,'Nieoczekiwany count override')
        if opcode==0x21 and write is None:
            if feature in (0x13,0x15) and lba==0 and read==512:
                need(self.pending_word is None,'Odczyt niszczacy niezuzyty parametr RAM');return
            if self.phase=='read' and feature==0x61 and lba==0x400 and read==512:
                need(self.pending_word is not None,'READ61 bez przekazanego adresu')
                self.pending_word=None;return
            if self.phase=='read' and feature==0x28 and lba==0 and read==512:return
            if self.phase=='auth' and feature==0xc5 and lba==0 and read==512:return
            if self.phase=='ram-verify' and feature==0x12 and lba==0:
                need(self.pending_sram is not None and read==self.pending_sram[1],'Brak parametru SRAM')
                self.pending_sram=None;return
            if self.phase=='verify' and feature==0x31:
                if not self.verify_header:
                    need(lba==0 and read==4096,'Pierwszy VERIFY musi byc naglowkiem')
                    self.verify_header=True;return
                index=self.verify_offset//65536
                expected=min(65536,len(self.assets.code)-self.verify_offset)
                need(expected>0 and lba==((index<<8)|0x10000) and read==expected,'Nieprawidlowa kolejnosc VERIFY')
                self.verify_offset+=read;return
        if opcode==0x31 and read==0 and isinstance(write,bytes):
            if self.phase=='read' and feature==0x24 and lba==0 and len(write)==512:
                a=struct.unpack_from('<I',write)[0]
                if a in WORDS and write==struct.pack('<I',a).ljust(512,b'\0'):
                    need(self.pending_word is None,'Niezuzyty parametr RAM')
                    self.pending_word=a;return
            if self.phase=='auth' and lba==0:
                if feature in (0xc4,0xc7) and write==bytes(512):return
                if feature==0xc6 and self.auth_answer is not None and write==self.auth_answer:return
            if self.phase in ('erase9','erase5') and feature==0x26:
                mode=9 if self.phase=='erase9' else 5
                # SBBQ61L3 60015484: mode09 requires LBA Low88, matching MP_API10073460.
                expected_lba=(mode<<16)|(0x88 if mode==9 else 0)
                if lba==expected_lba and write==bytes([mode])+bytes(511):return
            if self.phase=='format' and feature==0x08 and lba==0x21000:
                if self.assets.preformat is not None and write==self.assets.preformat:return
            if self.phase=='seed' and feature==0x80 and lba==0 and write==self.assets.seed:return
            if self.phase=='program' and feature==0x82:
                pos=self.next_chunk*65536;expected=self.assets.code[pos:pos+65536]
                need(bool(expected) and write==expected and lba==((self.next_chunk<<8)|0x10000),
                     'Kod82 niezgodny z przypietym firmware/kolejnoscia')
                self.next_chunk+=1;return
            if self.phase=='ram-verify' and feature==0x24 and lba==0 and len(write)==512:
                a=struct.unpack_from('<I',write)[0]
                for section in self.assets.layout:
                    start=section['burner_address'];end=start+section['size']
                    if start<=a<end and (a-start)%16384==0 and write==struct.pack('<I',a).ljust(512,b'\0'):
                        need(self.pending_sram is None,'Niezuzyty parametr SRAM')
                        self.pending_sram=(a,min(16384,end-a));return
            if self.phase=='commit' and feature==0x41 and lba==0x2000 and write==bytes(512):return
        raise RuntimeError('Komenda poza scisla lista etapu '+self.phase+': '+hex(opcode)+'/'+hex(feature))

class LinuxPort:
    def __init__(self,sg,path,gate,support,guard,trace,save,emit):
        import fcntl
        self.path=path;self.gate=gate;self.support=support;self.guard=guard
        self.trace=trace;self.save=save;self.emit=emit;self.counter=0;self.last=None
        self.fd=os.open(str(sg),os.O_RDWR|os.O_CLOEXEC)
        try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:os.close(self.fd);raise
        self.libc=c.CDLL(None,use_errno=True)
        self.libc.ioctl.argtypes=[c.c_int,c.c_ulong,c.c_void_p];self.libc.ioctl.restype=c.c_int

    def clean(self):
        self.guard()
        text=(self.trace.instance/'trace').read_text(errors='replace')
        need(trace_clean(text),'Kernel zarejestrowal blad/EH/reset ata4. STOP bez ponowien.')

    def close(self):os.close(self.fd)

    def command(self,opcode,feature=0,lba=0,write=None,read=0,count=0,timeout=30,label=None):
        try:
            self.gate.allow(opcode,feature,lba,write,read,count)
            self.clean()
        except BaseException:
            self.gate.failed=True;raise
        time.sleep(1)
        outgoing=write+bytes(-len(write)%512) if write is not None else None
        length=len(outgoing) if outgoing is not None else read
        cdb=make_cdb(opcode,feature,lba,length,outgoing is not None,count)
        cmd=c.create_string_buffer(cdb,len(cdb));data=c.create_string_buffer(max(length,1));sense=c.create_string_buffer(64)
        if outgoing is not None:c.memmove(data,outgoing,length)
        h=self.support.SgIoHdr();h.interface_id=ord('S');h.dxfer_direction=-2 if outgoing is not None else -3 if read else -1
        h.cmd_len=len(cdb);h.mx_sb_len=len(sense);h.dxfer_len=length
        h.dxferp=c.addressof(data) if length else None;h.cmdp=c.addressof(cmd);h.sbp=c.addressof(sense)
        h.timeout=int(timeout*1000);self.counter+=1;number=self.counter
        started=time.monotonic();gap=None if self.last is None else started-self.last
        self.emit(stage='command_start',number=number,phase=self.gate.phase,label=label,
                  cdb=cdb.hex(),bytes=length,timeout_seconds=timeout,gap_seconds=gap,
                  outgoing_sha256=sha(outgoing) if outgoing is not None else None)
        finished=threading.Event()
        def heartbeat():
            while not finished.wait(15):
                self.emit(stage='command_wait',number=number,phase=self.gate.phase,
                          elapsed_seconds=round(time.monotonic()-started),timeout_seconds=timeout)
        worker=threading.Thread(target=heartbeat,daemon=True);worker.start()
        try:
            c.set_errno(0);rc=self.libc.ioctl(self.fd,0x2285,c.byref(h));errno=c.get_errno() if rc<0 else 0
        finally:finished.set();worker.join(timeout=1)
        self.last=time.monotonic();elapsed=self.last-started
        raw_sense=sense.raw[:h.sb_len_wr];ata=parse_sense(raw_sense)
        good=completed_ok(rc,h.status,h.host_status,h.driver_status,h.resid,ata)
        received=data.raw[:read] if read else b''
        if read:self.save('cmd-%03d-%s.bin'%(number,'OK' if good else 'UNTRUSTED'),received)
        self.emit(stage='command_end',number=number,rc=rc,errno=errno,scsi=h.status,
                  host=h.host_status,driver=h.driver_status,residual=h.resid,ata=ata,
                  sense=raw_sense.hex(),seconds=elapsed,good=good)
        try:
            need(good,'Blad ATA/SG_IO przy '+str(label)+': '+repr(ata))
            if opcode in (0xe0,0xec) or (opcode==0x31 and feature==0x24):
                need(elapsed<5,'Podejrzanie dluga krotka komenda (>=5s); mozliwy ukryty timeout/reset')
            self.clean()
        except BaseException:
            self.gate.failed=True;raise
        return Reply(received,ata)

def unmounted(block,path):
    root=Path('/sys/class/block')/block.name;root=root.resolve(strict=True)
    devices=set()
    for entry in Path('/sys/class/block').iterdir():
        resolved=entry.resolve(strict=True)
        if resolved==root or resolved.parent==root:devices.add((entry/'dev').read_text().strip())
    need(bool(devices),'Brak major:minor badanego SSD')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        need(line.split()[2] not in devices,'Badany SSD lub partycja jest zamontowana')
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        try:
            st=os.stat(line.split()[0]);dev='%d:%d'%(os.major(st.st_rdev),os.minor(st.st_rdev))
            need(dev not in devices,'Swap na badanym SSD')
        except FileNotFoundError:pass

class Workflow:
    def __init__(self,port,assets,support,loader,save,emit,guard):
        self.port=port;self.a=assets;self.s=support;self.loader=loader
        self.save=save;self.emit=emit;self.guard=guard

    def vuc(self,feature,write=None,read=0,lba=0,timeout=30,label=None):
        key=self.port.command(0xe0,lba=0xfaeffe,count=0x6f,label=str(label)+' APKey')
        need(key.ata.get('count')==1 and key.ata.get('lbal')==1,'APKey nie potwierdzil klucza')
        return self.port.command(0x21 if read else 0x31,feature=feature,lba=lba,
                                 write=write,read=read,timeout=timeout,label=label)

    def info(self,label,engineering=False):
        r=self.vuc(0x13,read=512,label=label);self.save(label+'.bin',r.data)
        info=self.s.check_system(r.data,allow_engineering=engineering)
        self.emit(stage='system_info',label=label,**info);return info

    def word(self,address):
        need(address in WORDS and address%4==0,'Niedozwolony adres')
        self.vuc(0x24,write=struct.pack('<I',address).ljust(512,b'\0'),label='param-%08x'%address)
        r=self.vuc(0x61,read=512,lba=0x400,label='word-%08x'%address)
        need(r.data[:4]==struct.pack('<I',address),'Niezgodne echo adresu RAM')
        value=struct.unpack_from('<I',r.data,4)[0]
        self.emit(stage='memory_word',address=hex(address),value=hex(value))
        return value

    def snapshot(self,label):
        self.port.gate.phase='read';self.info(label+'-info')
        words={}
        for address in STATE_ADDRESSES:
            value=self.word(address);words[address]=value
            if address in CONTROLS:need(value==CONTROLS[address],'Niepoprawne slowo kontrolne burnera')
        self.save(label+'-words.json',json.dumps({hex(k):hex(v) for k,v in words.items()},indent=2).encode())
        return words

    def seed_check(self,label):
        self.port.gate.phase='read';self.info(label+'-info');actual={}
        for address in SEED_ADDRESSES:
            actual[address]=self.word(address)
            expected=self.a.expected.get(address)
            if expected is not None:need(actual[address]==expected,'Niezgodny readback seed przy '+hex(address))
            if address==0x5c0cdc44:need(actual[address]>>24==0,'Seed nie jest na poczatku strumienia')
        self.save(label+'-seed.json',json.dumps({hex(k):hex(v) for k,v in actual.items()},indent=2).encode())
        self.emit(stage='seed_readback',matched=True,label=label)

    def read_ib(self,label):
        self.port.gate.phase='read';r=self.vuc(0x28,read=512,label=label);self.save(label+'.bin',r.data)
        need(r.data[:6]==b'PhIsOn','InfoBlock nie ma PhIsOn')
        return r.data

    def prepare(self):
        self.port.gate.phase='read';r=self.port.command(0xec,read=512,label='fresh-identity')
        identity=self.s.ata_identity(r.data);self.emit(stage='fresh_identity',model=identity[0],firmware=identity[1])
        if identity==('PS3111','SBRM02.0'):
            self.guard();self.port.gate.phase='loader'
            iram,sram=self.loader.load_payloads(self.a.root)
            def cmd(opcode,**kwargs):return self.port.command(opcode,**kwargs).data
            self.loader.run_loader(cmd,self.emit,iram,sram)
            self.port.gate.phase='read'
        else:need(identity==('SATABURN SB','SBBQ61L3'),'Nie jest ROM/full burner badanego SSD')
        initial=self.info('after-loader',engineering=True)
        if initial['vuc_mode']==2:
            self.port.gate.phase='auth'
            self.vuc(0xc7,write=bytes(512),label='auth-reset')
            self.vuc(0xc4,write=bytes(512),label='auth-start')
            challenge=self.vuc(0xc5,read=512,label='auth-challenge').data
            first=self.s.cipher(challenge,1364702134)
            answer=self.s.cipher(first,1364702134^self.s.derive_seed(first))
            self.port.gate.auth_answer=answer;self.vuc(0xc6,write=answer,label='auth-answer')
        self.port.gate.phase='read';self.info('unlocked')
        ids=self.vuc(0x15,read=512,label='all-flash-ids').data
        need(all(ids[ce*8:ce*8+8]==FID for ce in CES),'NAND ID niezgodne z 8CE Toshiba BiCS3 tego CX400')
        self.save('all-flash-ids.bin',ids)
        return self.snapshot('preflight')

    def run(self,repair):
        before=self.prepare();flag=before[0x5c0cdafc]>>24
        if not repair:
            self.emit(result='PRECHECK_COMPLETE',info_block_flag=flag,nand_write=False)
            return 'PRECHECK_COMPLETE'
        reuse=False
        if flag==1:
            existing=self.read_ib('existing-infoblock')
            reuse=existing[0x57]==0x19
        else:need(flag==0,'Nieznana flaga InfoBlock; STOP zamiast kasowania')
        if reuse:
            self.emit(stage='reuse_preformat',note='Valid flag1 and PhIsOn; no repeat erase/preformat')
        else:
            self.emit(stage='factory_init_required',info_block_flag=flag,
                      note='No valid initialization or existing InfoBlock mode differs from updater Normal19')
            serial='CX4R'+datetime.datetime.now(datetime.timezone.utc).strftime('%y%m%d%H%M%S')+uuid.uuid4().hex[:4].upper()
            packet=self.a.build_preformat(serial);self.save('preformat-prepared.bin',packet)
            self.guard();self.info('before-factory-init')
            for mode in (9,5):
                self.port.gate.phase='erase%d'%mode
                self.vuc(0x26,write=bytes([mode])+bytes(511),lba=(mode<<16)|(0x88 if mode==9 else 0),
                         timeout=ERASE_TIMEOUT,label='erase-all-%02x'%mode)
                self.port.gate.phase='read';self.info('after-erase-%02x'%mode)
            self.port.gate.phase='format'
            self.vuc(0x08,write=packet,lba=0x21000,timeout=FORMAT_TIMEOUT,label='preformat-wait-completion')
            after=self.snapshot('after-preformat')
            need(after[0x5c0cdafc]>>24==1,'PreFormat nie ustawil flagi InfoBlock=1')
            ib=self.read_ib('after-preformat-infoblock')
            need(ib[0x12:0x4e]==packet[0x12:0x4e],'PreFormat readback SN/model niezgodny')
        self.port.gate.phase='seed'
        self.vuc(0x80,write=self.a.seed,label='normal-seed80')
        self.seed_check('after-normal-seed')
        self.port.gate.phase='program';self.port.gate.next_chunk=0
        last=None
        for pos in range(0,len(self.a.code),65536):
            i=pos//65536
            last=self.vuc(0x82,write=self.a.code[pos:pos+65536],lba=(i<<8)|0x10000,label='normal-code82-%02d'%i)
        need(last is not None and last.ata.get('lbah')==0xbb,'Brak znacznika BB poprawnych CRC kodu')
        self.emit(stage='normal_code_crc',marker='BB',all_chunks_sent=True)
        # All staging destinations are SRAM, not the IRAM byte-read crash path.
        self.port.gate.phase='ram-verify';staging_form=None
        for index,section in enumerate(self.a.layout):
            chunks=[]
            for pos in range(0,section['size'],16384):
                address=section['burner_address']+pos
                self.vuc(0x24,write=struct.pack('<I',address).ljust(512,b'\0'),label='staging-pointer')
                chunks.append(self.vuc(0x12,read=min(16384,section['size']-pos),label='staging-section%d-%05x'%(index,pos)).data)
            raw=b''.join(chunks);self.save('staging-section%d.bin'%index,raw)
            digest=sha(raw)
            form='plain' if digest==section['sha256'] else 'xor0561' if digest==section['xor0561_sha256'] else None
            need(form is not None,'Kod w SRAM niezgodny z oficjalnym SBFM61.3; commit41 NIE wyslany')
            need(staging_form is None or staging_form==form,'Mieszane reprezentacje sekcji SRAM; commit41 NIE wyslany')
            staging_form=form
            self.emit(stage='staging_verified',section=index,bytes=len(raw),sha256=digest,representation=form)
        self.guard();self.port.clean();self.port.gate.phase='commit'
        self.vuc(0x41,write=bytes(512),lba=0x2000,timeout=30,label='commit-firmware41')
        self.port.gate.phase='verify';self.port.gate.verify_header=False;self.port.gate.verify_offset=0
        header=self.vuc(0x31,read=4096,label='verify-flash-header').data;self.save('programmed-header.bin',header)
        need(header[:2]==b'ID','Niezgodny naglowek zapisu')
        need(self.s.crc32(header[:-8],0x31113111)==struct.unpack_from('<I',header,4092)[0],'Blad CRC naglowka z NAND')
        verified=[]
        for pos in range(0,len(self.a.code),65536):
            i=pos//65536;expected=self.a.code[pos:pos+65536]
            raw=self.vuc(0x31,read=len(expected),lba=(i<<8)|0x10000,label='verify-flash-code-%02d'%i).data
            need(raw==expected,'VERIFY_FLASH niezgodny w bloku '+str(i))
            verified.append(raw)
        self.save('programmed-code-readback.bin',b''.join(verified))
        self.snapshot('final');self.read_ib('final-infoblock')
        result='PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED'
        self.emit(result=result,nand_code_readback_bytes=len(self.a.code),normal_version='SBFM61.3',
                  note='Not yet a confirmed repaired SSD. Cold start and normal capacity verification required.')
        return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repair',action='store_true',help='Complete authorized destructive factory recovery attempt')
    args=parser.parse_args()
    need(sys.platform.startswith('linux') and os.geteuid()==0,'Wymagany Linux i sudo')
    root=Path(__file__).resolve().parent;a=Assets(root)
    # Assets were verified before importing loader/support, which have no import-time hardware access.
    sys.path.insert(0,str(root))
    import burner_loader as loader
    import service_probe as support
    import link_guard
    from trace_capture import Capture
    need(c.sizeof(support.SgIoHdr)==(88 if c.sizeof(c.c_void_p)==8 else 64),'SG_IO ABI mismatch')
    stamp=datetime.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')
    folder=Path.cwd()/('cx400-linux-recovery-result-'+stamp);folder.mkdir()
    lock=threading.Lock();records=[];status=1;port=None;trace=None
    with (folder/'report.txt').open('w',encoding='utf-8',buffering=1) as log:
        def emit(**fields):
            obj=dict(time=datetime.datetime.now().astimezone().isoformat(),**fields)
            with lock:
                line=json.dumps(obj,ensure_ascii=True);print(line,flush=True);log.write(line+'\n');records.append(obj)
        def save(name,data):
            need(Path(name).name==name,'Nieprawidlowa nazwa wyniku')
            (folder/name).write_bytes(data)
        def dmesg(name):
            p=subprocess.run(['dmesg','-T'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            save(name,p.stdout);emit(stage='dmesg',file=name,returncode=p.returncode)
        try:
            emit(stage='package',version=PACKAGE_VERSION,
                 script_sha256=sha(Path(__file__).read_bytes()),assets_sha256=ASSETS_SHA256)
            emit(mode='REPAIR' if args.repair else 'PRECHECK',kernel=os.uname().release,
                 assets_sha256=ASSETS_SHA256,normal_version='SBFM61.3')
            dmesg('dmesg-before.txt')
            block,size,path,sg,cached=support.select_device()
            def guard():
                need((Path('/sys/class/scsi_generic')/sg.name/'device').resolve(strict=True)==path,'Zmiana przypisania sg')
                unmounted(block,path)
                return link_guard.require_link(path,Path('/proc/cmdline').read_text())
            details=guard();emit(stage='target',block=str(block),sg=str(sg),path=str(path),cached_model=cached,**details)
            trace=Capture(path,folder,emit);trace.start();(trace.instance/'buffer_size_kb').write_text('8192\n')
            port=LinuxPort(sg,path,Gate(a,loader),support,guard,trace,save,emit)
            workflow=Workflow(port,a,support,loader,save,emit,guard)
            outcome=workflow.run(args.repair);status=0
        except (Exception,KeyboardInterrupt) as exc:
            emit(result='STOPPED_WITHOUT_RETRY',error=str(exc),
                 note='Do not repeat erase/seed/program automatically. Result archive includes transport and kernel trace.')
        finally:
            if port is not None:port.close()
            if trace is not None:trace.close()
            try:dmesg('dmesg-after.txt')
            except Exception as exc:emit(dmesg_error=str(exc))
            save('report.json',json.dumps(records,indent=2).encode())
    archive=folder.with_suffix('.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for item in sorted(folder.iterdir()):
            if item.is_file():z.write(item,item.name)
    print('RESULT ZIP: '+str(archive),flush=True)
    if status==0 and args.repair:
        print('Shut down and remove SSD power before checking normal capacity. Repair is not confirmed by this script alone.')
    return status

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        print('STOP before hardware: '+str(error),file=sys.stderr);sys.exit(2)
