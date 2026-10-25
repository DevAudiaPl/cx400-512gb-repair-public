"""Pure data/guard tests only. Never invokes main, fio, SMART or a block device."""
from pathlib import Path
import ast
import copy
import importlib.util
import json

root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cx400_test',root/'cx400-test.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
count=0
def ok(value,label):
    global count
    if not value:raise AssertionError(label)
    count+=1
def fails(call,label):
    try:call()
    except (RuntimeError,KeyError):ok(True,label)
    else:raise AssertionError(label)

disk=dict(name='/dev/sda',size=m.CAPACITY,model='SATA SSD',serial=m.SERIAL,tran='sata',type='disk',ro=False,mountpoints=[None])
healthy=dict(name='/dev/sdb',size=120034123776,model='Intenso SSD',serial='SYNTHETIC_HEALTHY_DISK',tran='sata',type='disk',ro=False,mountpoints=['/'])
tree=dict(blockdevices=[healthy,disk])
ok(m.select_device(tree)[0]['serial']==m.SERIAL,'select exact recovered SSD among mounted healthy disks')
fails(lambda:m.select_device(dict(blockdevices=[healthy])),'missing target')
fails(lambda:m.select_device(dict(blockdevices=[disk,disk])),'ambiguous target')
for change in (dict(size=120034123776),dict(model='GOODRAM CX400'),dict(tran='usb'),dict(ro=True),dict(mountpoints=['/mnt'])):
    bad=dict(disk,**change)
    fails(lambda:m.select_device(dict(blockdevices=[bad])),'device guard '+str(change))
for mount in ('/','/home','[SWAP]'):
    bad=copy.deepcopy(disk);bad['children']=[dict(name='/dev/sda1',type='part',mountpoints=[mount])]
    fails(lambda:m.select_device(dict(blockdevices=[bad])),'mounted child '+mount)
smart=dict(serial_number=m.SERIAL,firmware_version=m.FIRMWARE,user_capacity=dict(bytes=m.CAPACITY),
           logical_block_size=512,smart_status=dict(passed=True),power_cycle_count=2)
ok(m.check_smart(smart)==smart,'normal SMART exact identity')
for change in (dict(serial_number='SYNTHETIC_HEALTHY_DISK'),dict(firmware_version='SBRM02.0'),
               dict(user_capacity=dict(bytes=20971520)),dict(logical_block_size=4096),dict(smart_status=dict(passed=False))):
    fails(lambda:m.check_smart(dict(smart,**change)),'SMART guard '+str(change))
ok(m.power_cycles(smart)==2,'JSON cycle count')
ok(m.power_cycles(dict(ata_smart_attributes=dict(table=[dict(id=12,raw=dict(value=3))])))==3,'attribute cycle fallback')
fails(lambda:m.power_cycles({}),'missing cycle count')
state=dict(status='WRITE_COMPLETE',serial=m.SERIAL,capacity=m.CAPACITY,firmware=m.FIRMWARE,
           write_boot_id='old-boot',write_after_power_cycles=1)
m.verify_state(state,smart,'new-boot');ok(True,'completed write and cold cycle accepted')
for change in (dict(status='PREPARING'),dict(serial='other'),dict(capacity=20971520),dict(firmware='SBRM02.0')):
    fails(lambda:m.verify_state(dict(state,**change),smart,'new-boot'),'state guard '+str(change))
fails(lambda:m.verify_state(state,smart,'old-boot'),'same boot rejected')
fails(lambda:m.verify_state(state,dict(smart,power_cycle_count=1),'new-boot'),'warm boot without SSD power cycle rejected')
jobs=m.plan(m.CAPACITY)
ok(jobs[0]==('cx400-bulk',0,512109838336,1048576),'independent exact bulk range')
ok(jobs[1]==('cx400-tail',512109838336,352256,4096),'independent tail range, no truncation')
ok(sum(j[2] for j in jobs)==512110190592,'every advertised byte covered once')
for size in (4096,1048576,1048576+4096,7*1048576+352256):
    result=m.plan(size);ok(sum(j[2] for j in result)==size and result[-1][1]+result[-1][2]==size,'small boundary '+str(size))
fails(lambda:m.plan(m.CAPACITY+512),'unaligned last block rejected')
pattern='0123456789abcdef0123456789abcdef'
for mode in ('write','verify'):
    text=m.job_text('/dev/sda',m.CAPACITY,mode,pattern)
    ok(text.count('filename=/dev/sda')==1 and 'verify=pattern' in text and 'verify_interval=4096' in text,'fio verification and target '+mode)
    ok('rw='+('write' if mode=='write' else 'read') in text,'correct direction '+mode)
    ok('size=512109838336' in text and 'offset=512109838336' in text and 'size=352256' in text,'fio includes full tail '+mode)
    ok('allow_file_create=0' in text and 'allow_mounted_write=0' in text,'fio file safeguards '+mode)
    output=dict(jobs=[dict(jobname=name,error=0,read=dict(io_bytes=length if mode=='verify' else 0),
                          write=dict(io_bytes=length if mode=='write' else 0)) for name,off,length,bs in jobs])
    ok(m.check_fio(output,m.CAPACITY,mode)==m.CAPACITY,'accept exact fio counters '+mode)
    bad=copy.deepcopy(output);bad['jobs'][0]['error']=84
    fails(lambda:m.check_fio(bad,m.CAPACITY,mode),'fio verification failure '+mode)
    bad=copy.deepcopy(output);bad['jobs'][1]['write' if mode=='write' else 'read']['io_bytes']-=4096
    fails(lambda:m.check_fio(bad,m.CAPACITY,mode),'incomplete tail '+mode)
    bad=copy.deepcopy(output);bad['jobs'][1]['read' if mode=='write' else 'write']['io_bytes']=4096
    fails(lambda:m.check_fio(bad,m.CAPACITY,mode),'unexpected direction '+mode)
fails(lambda:m.job_text('/dev/sda\nrw=write',m.CAPACITY,'verify',pattern),'job injection rejected')
fails(lambda:m.job_text('/dev/sda',m.CAPACITY,'verify','oops'),'invalid pattern rejected')
source=(root/'cx400-test.py').read_text(encoding='utf-8');ast.parse(source)
ok("if mode=='verify':command+=['--readonly']" in source,'read-only fio boundary in verify')
ok("need(not state_path.exists()" in source,'no repeat write after state creation')
ok("sample.open('xb')" in source and "stat.S_ISREG(sample.stat().st_mode)" in source,'installed-fio selfcheck uses new regular file')
ok('sanity-wrong-pattern-EXPECTED' in source and 'sanity-corruption-EXPECTED' in source,'installed-fio negative checks present')
ok('fallocate' not in source and 'mkfs' not in source and 'sg_io' not in source.lower(),'no partition or firmware commands')
print('PASS',count,'offline data/guard checks; no fio, SMART or block device was invoked')
