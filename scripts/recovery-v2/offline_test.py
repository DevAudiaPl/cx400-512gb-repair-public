"""Offline tests only. Fake transport; no LinuxPort constructor or real ioctl."""
from pathlib import Path
import ctypes as c
import importlib.util
import hashlib
import json
import struct
import sys
import tempfile
import types
from unittest.mock import patch

root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parent
sys.path.insert(0,str(root))
spec=importlib.util.spec_from_file_location('recovery',root/'cx400-recover.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
import burner_loader as loader
import service_probe as support

count=0
def check(value,label):
    global count
    if not value:raise AssertionError(label)
    count+=1

assets=m.Assets(root)
captured=json.loads((root/'regression-184055.json').read_text(encoding='utf-8-sig'))
real_info=bytes(captured['Commands'][2]['Data'])
real_id=bytes(captured['Commands'][0]['Data'])
def identify(model='SATABURN SB',fw='SBBQ61L3'):
    raw=bytearray(real_id)
    for offset,size,value in ((46,8,fw),(54,40,model)):
        b=value.encode().ljust(size,b' ')
        raw[offset:offset+size]=b''.join(b[i:i+2][::-1] for i in range(0,size,2))
    return bytes(raw)


# Frozen raw bytes from the actual burner and MP_API, plus real failed packet.
# This models one audited firmware guard; it is not CPU or hardware emulation.
guard_raw=(root/'erase09-burner-guard.bin').read_bytes()
host_raw=(root/'erase09-host-frame.bin').read_bytes()
check(hashlib.sha256(guard_raw).hexdigest()=='ee0a06fc951d9f7fde6abcf4efe92cc9501ffaba0482bec733e0b7ee6590df82','frozen actual SBBQ guard bytes')
check(hashlib.sha256(host_raw).hexdigest()=='6d8d6595c1f1a6358d5cc4c7da798abd8980105b6c85a2ae26874f7536d65ae8','independent MP_API frame bytes')
check(guard_raw[9:12]==bytes.fromhex('82a088'),'actual Xtensa MOVI88 in erase09 receiver')
check(bytes.fromhex('80fb097505b888000000') in host_raw,'actual x86 mode09 selects88')
magic=guard_raw[11]
def burner_erase_guard(cdb):
    # 60015487 reads LBA High; branch6001548a bypasses mode09 guard otherwise.
    # 60015493 reads LBA Low; branch60015498 accepts only the MOVI88 value.
    return cdb[7]!=9 or cdb[5]==magic
real_failed=json.loads((root/'regression-212838.json').read_text())
old_cdb=bytes.fromhex(real_failed['command_start']['cdb'])
check(not burner_erase_guard(old_cdb),'real212838 old packet takes explicit ABRT branch')
real_ata=m.parse_sense(bytes.fromhex(real_failed['command_end']['sense']))
check(real_ata['error']==4 and real_ata['status']==0x51 and not m.completed_ok(0,2,0,8,0,real_ata),'real212838 fixed sense is ATA rejection')
check(real_failed['command_end']['seconds']<0.1,'real212838 was immediate rejection, not long erase timeout')

class FakePort:
    def __init__(self,flag=0):
        self.gate=m.Gate(assets,loader);self.commands=[];self.memory=dict.fromkeys(m.WORDS,0)
        self.memory.update(m.CONTROLS);self.memory[0x5c0cdafc]=flag<<24
        self.info=real_info;self.id=real_id;self.scratch=b'';self.sram_ptr=0
        self.fail=None;self.bad_seed=False;self.bad_stage=False;self.bad_nand=False
        self.bad_ib=False;self.missing_flag=False;self.no_bb=False;self.bad_echo=False
        self.bad_fid=False;self.bad_header=False;self.saved={};self.events=[]
        self.stage_xor=False;self.mixed_xor=False
        self.erase_count=0;self.preformat_count=0;self.commit_count=0;self.seed_count=0
        self.program_count=0;self.verify_count=0;self.verify_pos=0
        self.loaded_iram={};self.loaded_sram={}
        self.old_ib=assets.build_preformat('CX4R261024120000ABCD')[:512]
    def clean(self):pass
    def command(self,opcode,feature=0,lba=0,write=None,read=0,count=0,timeout=30,label=None):
        self.gate.allow(opcode,feature,lba,write,read,count)
        self.commands.append((opcode,feature,lba,write,read,count,timeout,label))
        if self.fail is not None and self.fail==label:
            self.gate.failed=True;raise RuntimeError('Injected device/transport failure at '+label)
        ata=dict(error=0,status=0x50,count=1,lbal=1,lbah=0,lbam=0);data=b''
        if opcode==0xec:data=self.id
        elif opcode==0xe0:pass
        elif feature==0x13:data=self.info
        elif feature==0x15:
            b=bytearray(512)
            for ce in m.CES:b[ce*8:ce*8+8]=m.FID
            if self.bad_fid:b[8*8]^=1
            data=bytes(b)
        elif feature==0x24:
            self.scratch=write;self.sram_ptr=struct.unpack_from('<I',write)[0]
        elif feature==0x40:
            address,size=struct.unpack('<II',self.scratch)
            check(len(write)==size,'loader command40 exact length')
            self.loaded_iram[address]=write
        elif feature==0x30:
            address,size=struct.unpack('<II',self.scratch)
            collected=b''.join(self.loaded_iram[a] for a in sorted(self.loaded_iram) if address<=a<address+size)
            ref=next((root/name).read_bytes() for name,start,length,d in loader.SECTIONS if start==address and length==size)
            check(collected==ref,'loader IRAM independent full data equality')
            data=struct.pack('<8xI',0x55aa55aa).ljust(512,b'\0')
        elif feature==0x0f:self.id=identify()
        elif feature==0xbd:self.loaded_sram[lba>>16]=write
        elif feature==0xbe:data=self.loaded_sram[lba>>16]
        elif feature in (0xc4,0xc7):pass
        elif feature==0xc5:data=bytes(range(256))*2
        elif feature==0xc6:
            b=bytearray(self.info);b[0x1aa]=3;self.info=bytes(b)
        elif feature==0x61:
            a=struct.unpack_from('<I',self.scratch)[0]
            data=struct.pack('<II',a,self.memory[a]).ljust(512,b'\0')
            if self.bad_echo:data=bytes([data[0]^1])+data[1:]
        elif feature==0x26:
            check(burner_erase_guard(m.make_cdb(opcode,feature,lba,len(write),True)),
                  'command reaches erase body past independently extracted guard')
            self.erase_count+=1
        elif feature==0x08:
            self.preformat_count+=1;self.old_ib=write[:512]
            if not self.missing_flag:self.memory[0x5c0cdafc]=0x01000000
        elif feature==0x28:
            data=self.old_ib
            if self.bad_ib:data=b'X'+data[1:]
        elif feature==0x80:
            self.seed_count+=1;self.memory.update(assets.expected);self.memory[0x5c0cdc44]=0
            if self.bad_seed:self.memory[0x5c0cdc38]=0
        elif feature==0x82:
            self.program_count+=1
            if self.program_count==12 and not self.no_bb:ata['lbah']=0xbb
        elif feature==0x12:
            for section in assets.layout:
                start=section['burner_address']
                if start<=self.sram_ptr<start+section['size']:
                    pos=self.sram_ptr-start;data=(root/section['file']).read_bytes()[pos:pos+read]
                    if self.stage_xor or (self.mixed_xor and section['file']=='normal-section1.bin'):
                        stream=(root/'regression-xor0561.bin').read_bytes()
                        data=bytes(x^y for x,y in zip(data,stream[:read]))
                    break
            else:raise AssertionError('SRAM read out of staging ranges')
            if self.bad_stage:data=bytes([data[0]^1])+data[1:]
        elif feature==0x41:self.commit_count+=1
        elif feature==0x31:
            self.verify_count+=1
            if read==4096:
                b=bytearray(4096);b[:2]=b'ID'
                struct.pack_into('<I',b,4092,support.crc32(b[:-8],0x31113111));data=bytes(b)
                if self.bad_header:data=data[:4092]+bytes(4)
            else:
                data=assets.code[self.verify_pos:self.verify_pos+read];self.verify_pos+=read
                if self.bad_nand:data=bytes([data[0]^1])+data[1:]
        else:raise AssertionError('Missing fake operation '+str((opcode,feature)))
        return m.Reply(data,ata)

def run_fake(p,repair=True):
    flow=m.Workflow(p,assets,support,loader,lambda n,b:p.saved.__setitem__(n,b),
                    lambda **e:p.events.append(e),lambda:None)
    return flow.run(repair)

def fails(p,label,commit=0):
    try:run_fake(p)
    except RuntimeError as e:check(bool(str(e)),label+' exception')
    else:raise AssertionError(label+' did not stop')
    check(p.commit_count==commit,label+' commit boundary')

check(support.check_system(real_info)['vuc_mode']==3,'real captured184055 geometry')
check(m.sha(assets.seed)=='ccb6eac296080e754bafece672399a824d7cdbc72c9dec0048c3fa5d5c5a8872','exact original normal seed')
check(m.sha(assets.normal)=='c73d0b4d06bc44be913f4876f9fc21935ca4f6f51fce3b2c4f95f80add3f7d1e','exact full normal image')
check(sum(s['size'] for s in assets.layout)==len(assets.code)==770048,'all six sections accounted')
for section in assets.layout:
    data=(root/section['file']).read_bytes()
    check(support.crc32(data[:-8],0x55aa55aa)==struct.unpack_from('<I',data,len(data)-4)[0],'independent plaintext CRC '+section['file'])

pkt=assets.build_preformat('CX4R261024120000ABCD')
check(len(pkt)==1024 and pkt[:6]==b'PhIsOn','default preformat two sectors')
check(pkt[0x57]==0x19 and pkt[0x62]==3 and pkt[0x6b:0x6d]==b'\x03\x07','updater InfoBlock offsets')
check(pkt[0x1f5:0x1fa]==b'DWN\x01\0' and pkt[512:]==assets.smart,'updater default trailer and correct SMART template')
check(support.word_string(pkt[0x12:0x26])=='CX4R261024120000ABCD','SN word order')
check(support.word_string(pkt[0x26:0x4e])=='SATA SSD','model word order')

p=FakePort();check(run_fake(p)=='PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED','complete factory attempt')
check((p.erase_count,p.preformat_count,p.seed_count,p.program_count,p.commit_count,p.verify_count)==(2,1,1,12,1,13),'exact destructive stages once each')
check(p.saved['programmed-code-readback.bin']==assets.code,'full ciphertext NAND verification')
for i,s in enumerate(assets.layout):check(m.sha(p.saved['staging-section%d.bin'%i])==s['sha256'],'independent full staged RAM hash '+str(i))
erases=[x for x in p.commands if x[1]==0x26]
check([(x[2],x[3][0],x[6]) for x in erases]==[(0x90088,9,960),(0x50000,5,960)],'actual Q-burner-compatible MP_API erase frames')
format_cmd=next(x for x in p.commands if x[1]==8)
check(format_cmd[2]==0x21000 and len(format_cmd[3])==1024 and format_cmd[6]==1280,'x86 updater golden PreFormat frame')
commit=next(x for x in p.commands if x[1]==0x41)
check(commit[2]==0x2000 and commit[3]==bytes(512),'x86 updater golden commit41 frame')

p=FakePort(1);check(run_fake(p)=='PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED','reuse valid existing initialization')
check(p.erase_count==p.preformat_count==0 and p.seed_count==p.commit_count==1,'reuse never repeats erase or PreFormat')
p=FakePort(1);ib=bytearray(p.old_ib);ib[0x57]=5;p.old_ib=bytes(ib)
check(run_fake(p)=='PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED' and p.erase_count==2 and p.preformat_count==1,'old non-Normal InfoBlock requires factory initialization')
p=FakePort();check(run_fake(p,False)=='PRECHECK_COMPLETE','bounded precheck')
check(p.erase_count==p.preformat_count==p.seed_count==p.program_count==p.commit_count==0,'precheck no persistent operations or seed')

for flag in (2,255):
    p=FakePort(flag);fails(p,'unknown SA flag '+str(flag));check(p.erase_count==0,'unknown flag refuses erase')
for model,fw in [('GOODRAM CX400','SBFM61.3'),('Intenso SSD','Q1107A0'),('PS3111','SBRM01.0')]:
    p=FakePort();p.id=identify(model,fw);fails(p,'identity '+model)
    check(len(p.commands)==1,'other target only IDENTIFY')
for offset in (0,2,3,4,0x148,0x149,0x16b,0x1a8,0x1a9):
    p=FakePort();b=bytearray(p.info);b[offset]^=1;p.info=bytes(b);fails(p,'geometry/mode '+hex(offset))
    check(p.erase_count==0,'no erase wrong geometry')
for mode in (0,1,4,255):
    p=FakePort();b=bytearray(p.info);b[0x1aa]=mode;p.info=bytes(b);fails(p,'unknown VUC mode '+str(mode))
    check(p.erase_count==0,'unknown VUC no erase')
p=FakePort(1);b=bytearray(p.info);b[0x1aa]=2;p.info=bytes(b)
check(run_fake(p)=='PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED','engineering mode actual auth cipher flow')
check([x[1] for x in p.commands if x[1] in (0xc4,0xc5,0xc6,0xc7)]==[0xc7,0xc4,0xc5,0xc6],'auth commands exact order once')
p=FakePort();p.id=identify('PS3111','SBRM02.0')
check(run_fake(p,False)=='PRECHECK_COMPLETE','actual original checked loader flow from ROM')
check(len(p.loaded_sram)==8 and p.erase_count==0,'full SRAM loader verified without erase')
p=FakePort();p.bad_fid=True;fails(p,'actual NAND ID changed');check(p.erase_count==0,'NAND ID protects erase')
p=FakePort();p.memory[0x5c0e0400]^=1;fails(p,'control failed');check(p.erase_count==0,'no erase failed control')
p=FakePort();p.bad_echo=True;fails(p,'address echo failed');check(p.erase_count==0,'no erase failed echo')
p=FakePort(1);p.bad_ib=True;fails(p,'existing invalid InfoBlock');check(p.erase_count==0,'do not auto-erase unrecognized valid flag')
for label in ('erase-all-09','after-erase-09','erase-all-05','preformat-wait-completion','after-preformat-info'):
    p=FakePort();p.fail=label;fails(p,'failure '+label)
    check(p.seed_count==0,'no seed after failed initialization '+label)
p=FakePort();p.missing_flag=True;fails(p,'PreFormat API success but invalid flag');check(p.seed_count==0,'valid flag required after PreFormat')
p=FakePort(1);p.bad_seed=True;fails(p,'seed success without actual key');check(p.program_count==0,'no82 without key readback')
p=FakePort(1);p.fail='normal-code82-05';fails(p,'middle82 error');check(p.program_count==5,'no repeat of failed program chunk')
p=FakePort(1);p.no_bb=True;fails(p,'no final CRC BB marker')
p=FakePort(1);p.bad_stage=True;fails(p,'SRAM plaintext mismatch prevents commit')
p=FakePort(1);p.stage_xor=True
check(run_fake(p)=='PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED','full XOR0561 staging of exact original file accepted')
check(all(e.get('representation')=='xor0561' for e in p.events if e.get('stage')=='staging_verified'),'same XOR form across all6 sections')
p=FakePort(1);p.mixed_xor=True;fails(p,'mixed SRAM representations prevent commit')
p=FakePort(1);p.bad_nand=True;fails(p,'NAND ciphertext mismatch',commit=1);check(p.verify_count==2,'stop after first failed NAND block')
p=FakePort(1);p.bad_header=True;fails(p,'NAND header CRC mismatch',commit=1);check(p.verify_count==1,'no code read after invalid header')

# Low-level exact wire oracle: x86 updater fields translated into SAT12.
check(m.make_cdb(0x31,0x26,0x90088,512,True).hex()=='a10a262601880009a0310000','golden erase09 SAT12')
check(m.make_cdb(0x31,0x08,0x21000,1024,True).hex()=='a10a260802001002a0310000','golden PreFormat SAT12')
check(m.make_cdb(0x31,0x41,0x2000,512,True).hex()=='a10a264101002000a0310000','golden commit SAT12')
check(m.make_cdb(0xe0,0,0xfaeffe,0,False,0x6f).hex()=='a10620006ffe effaafe00000'.replace(' ',''),'APKey AF exact wire')
check(m.make_cdb(0x31,0x82,0x10b00,49152,True).hex()=='a10a268260000b01a0310000','last normal chunk oracle')

for feature in (0x08,0x26,0x41,0x80,0x82,0x16,0x60,0x20,0x22,0x25,0x0f):
    g=m.Gate(assets,loader)
    try:g.allow(0x31,feature,0,bytes(512),0,0)
    except RuntimeError:check(True,'blocked write outside phase '+hex(feature))
    else:raise AssertionError('unexpected write admitted')
for address in (0,0x04006f80,0x5c0cdc39,0x50000000):
    g=m.Gate(assets,loader)
    try:g.allow(0x31,0x24,0,struct.pack('<I',address).ljust(512,b'\0'),0,0)
    except RuntimeError:check(True,'disallowed pointer '+hex(address))
    else:raise AssertionError('bad pointer admitted')
g=m.Gate(assets,loader)
try:g.allow(0x21,0x61,0x400,None,512,0)
except RuntimeError:check(True,'61 requires parameter')
else:raise AssertionError('61 without parameter')


# Admission boundary rejects the previously wrong frame and other magic variants.
check(burner_erase_guard(m.make_cdb(0x31,0x26,0x90088,512,True)),'corrected packet passes actual guard condition')
check(m.make_cdb(0x31,0x26,0x90088,512,True).hex()==real_failed['expected_corrected_cdb'],'independent corrected frame oracle')
for phase,lba,mode in [('erase9',0x90000,9),('erase9',0x90089,9),('erase9',0x98800,9),('erase9',0x50088,9),('erase5',0x50088,5)]:
    g=m.Gate(assets,loader);g.phase=phase
    try:g.allow(0x31,0x26,lba,bytes([mode])+bytes(511),0,0)
    except RuntimeError:check(True,'reject wrong erase frame '+phase+' '+hex(lba))
    else:raise AssertionError('incorrect erase frame admitted')

# Both Linux sense formats, including actual Windows SCSI0 / ATA04/51.
descriptor=bytes.fromhex('7201001d0000000e090c00000001000100040000a050')
fixed=bytes.fromhex('f000000050a0010a00000400001d00000000')
for raw in (descriptor,fixed):
    a=m.parse_sense(raw);check(a['status']==0x50 and a['lbam']==4,'parse complete ATA registers '+a['format'])
    check(m.completed_ok(0,2,0,8,0,a),'informational CK_COND '+a['format'])
a=m.parse_sense(bytes.fromhex(captured['Commands'][-1]['Sense'].replace(' ','')))
check(a['error']==4 and a['status']==0x51 and not m.completed_ok(0,0,0,0,0,a),'actual184055 SCSI0/ATAABRT must fail')
for changed in ({'status':0x51,'error':4},{'status':0xd0},{'status':0x58},{'status':0x70},{'sense_key':11},{'asc':0x20}):
    a=m.parse_sense(descriptor);a.update(changed);check(not m.completed_ok(0,2,0,8,0,a),'reject sense '+str(changed))
for args in ((-1,2,0,8,0),(0,8,0,0,0),(0,2,1,8,0),(0,2,0,16,0),(0,2,0,8,512)):
    check(not m.completed_ok(*args,m.parse_sense(descriptor)),'reject bad SG status '+str(args))
check(m.trace_clean('# harmless header\nx ata_qc_issue: ...\nx ata_qc_complete_done: ...'),'good trace')
for event in ('ata_qc_complete_failed','ata_eh_link_autopsy','ata_eh_link_autopsy_qc','ata_link_hardreset_begin','ata_link_softreset_begin'):
    check(not m.trace_clean('worker '+event+': data'),'block kernel event '+event)

original_read=Path.read_bytes
for filename in ('assets.json','normal-SBFM61.3.bin','normal-section0.bin','smart-template.bin'):
    def damaged(path):
        b=original_read(path)
        return bytes([b[0]^1])+b[1:] if path.name==filename else b
    with patch.object(Path,'read_bytes',damaged):
        try:m.Assets(root)
        except RuntimeError:check(True,'corrupt asset refused before device access '+filename)
        else:raise AssertionError('corrupt asset admitted')

# Exercise actual ctypes packet construction with an in-memory fake ioctl.
# LinuxPort.__init__ is deliberately NEVER called, so no os.open/flock/CDLL.
class FakeIoctl:
    def __init__(self,clock,slow=False,abort=False):self.clock=clock;self.slow=slow;self.abort=abort;self.calls=0
    def ioctl(self,fd,code,ref):
        check(fd==-1 and code==0x2285,'fake-only ioctl marker');self.calls+=1
        h=ref._obj;raw=c.string_at(h.cmdp,h.cmd_len)
        check(raw==m.make_cdb(0xec,0,0,512,False),'actual native packet ABI contains expected CDB')
        sense=bytearray(descriptor)
        if self.abort:sense[11]=4;sense[21]=0x51
        c.memmove(h.sbp,bytes(sense),len(sense));c.memmove(h.dxferp,real_id,512)
        h.sb_len_wr=len(sense);h.status=2;h.host_status=0;h.driver_status=8;h.resid=0
        self.clock[0]+=16 if self.slow else 0.001;return 0
for slow,abort in ((False,False),(True,False),(False,True)):
    clock=[0.0];g=m.Gate(assets,loader);p=object.__new__(m.LinuxPort)
    p.path=None;p.gate=g;p.support=support;p.fd=-1;p.counter=0;p.last=None
    p.emit=lambda **x:None;p.save=lambda n,b:None;p.clean=lambda:None;p.libc=FakeIoctl(clock,slow,abort)
    with patch.object(m.time,'sleep',lambda x:clock.__setitem__(0,clock[0]+x)),patch.object(m.time,'monotonic',lambda:clock[0]):
        if slow or abort:
            try:p.command(0xec,read=512,label='fake-id')
            except RuntimeError:check(g.failed,'bad native result freezes further commands')
            else:raise AssertionError('bad native result accepted')
        else:check(p.command(0xec,read=512).data==real_id,'native good fake data')
    check(p.libc.calls==1,'one ioctl; no retry')

print('PASS',count,'offline checks; fake devices and in-memory fake ioctl only; no hardware access')
