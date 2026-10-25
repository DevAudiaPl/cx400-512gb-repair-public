#!/usr/bin/env python3
"""One full user-area write and a separate post-power-cycle pattern read for CX400.
Linux only. No firmware commands. Fixed serial/capacity/firmware; no target option.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess as sp
import sys
import time
import zipfile

SERIAL='CX4R2610242000213B51'
CAPACITY=512110190592
FIRMWARE='SBFM61.3'
MIB=1048576

def need(ok,message):
    if not ok:raise RuntimeError(message)

def digest(data):return hashlib.sha256(data).hexdigest()

def walk(nodes):
    for n in nodes:
        yield n
        yield from walk(n.get('children',[]))

def select_device(tree):
    matches=[n for n in walk(tree['blockdevices']) if n.get('type')=='disk' and n.get('serial')==SERIAL]
    need(len(matches)==1,'Wymagany dokładnie jeden dysk o numerze '+SERIAL)
    disk=matches[0]
    need(int(disk.get('size',0))==CAPACITY and disk.get('model','').strip()=='SATA SSD',
         'Nieprawidłowy model lub pojemność CX400')
    need(disk.get('tran')=='sata' and not disk.get('ro'),'Wymagane natywne SATA i brak blokady RO')
    nodes=list(walk([disk]))
    need(all(not any(n.get('mountpoints') or []) for n in nodes),
         'CX400 lub jego partycja jest zamontowana/swap. STOP.')
    return disk,nodes

def check_smart(obj):
    need(obj.get('serial_number')==SERIAL and obj.get('firmware_version')==FIRMWARE,
         'SMART nie potwierdził numeru seryjnego i SBFM61.3')
    need(obj.get('user_capacity',{}).get('bytes')==CAPACITY,'SMART: niezgodna pojemność')
    need(obj.get('logical_block_size')==512,'Nieprawidłowy rozmiar sektora')
    need(obj.get('smart_status',{}).get('passed') is True,'SMART nie zgłasza PASSED')
    return obj

def power_cycles(obj):
    value=obj.get('power_cycle_count')
    if isinstance(value,int):return value
    for item in obj.get('ata_smart_attributes',{}).get('table',[]):
        if item.get('id')==12:
            value=item.get('raw',{}).get('value')
            if isinstance(value,int):return value
    raise RuntimeError('Brak licznika Power_Cycle_Count w SMART')

def verify_state(state,before,boot):
    need(state.get('status')=='WRITE_COMPLETE' and state.get('serial')==SERIAL
         and state.get('capacity')==CAPACITY and state.get('firmware')==FIRMWARE,
         'Brak stanu zakończonego pełnego zapisu w tym katalogu')
    need(boot!=state['write_boot_id'],'Odczyt wymaga ponownego uruchomienia po odcięciu zasilania SSD')
    need(power_cycles(before)>state['write_after_power_cycles'],
         'Licznik nie potwierdza odłączenia zasilania SSD po zapisie')

def plan(size):
    need(size>0 and size%4096==0,'Test wymaga wielokrotności4096B')
    bulk=size//MIB*MIB
    jobs=[]
    if bulk:jobs.append(('cx400-bulk',0,bulk,MIB))
    if size>bulk:jobs.append(('cx400-tail',bulk,size-bulk,4096))
    need(sum(s for _,_,s,_ in jobs)==size,'Niepełne pokrycie zakresu')
    return jobs

def job_text(device,size,mode,pattern):
    need(mode in ('write','verify'),'Tryb testu')
    need(re.fullmatch(r'[0-9a-f]{32}',pattern) is not None,'Wzorzec testowy')
    need('\n' not in str(device) and ':' not in str(device),'Nieprawidłowa ścieżka fio')
    lines=['[global]',f'filename={device}','ioengine=libaio','iodepth=16',
           'direct=1','numjobs=1','loops=1','allow_file_create=0','allow_mounted_write=0',
           'rw='+('write' if mode=='write' else 'read'),'verify=pattern',
           'verify_interval=4096','verify_pattern=0x'+pattern,'verify_fatal=1',
           'verify_dump=0','verify_state_save=0','verify_header_seed=0','verify_write_sequence=0',
           'do_verify='+('0' if mode=='write' else '1'),
           'end_fsync='+('1' if mode=='write' else '0')]
    for index,(name,offset,length,bs) in enumerate(plan(size)):
        lines+=['',f'[{name}]',f'offset={offset}',f'size={length}',f'bs={bs}']
        if index:lines+=['stonewall=1']
    return '\n'.join(lines)+'\n'

def parse_fio(text):
    """fio 3.x may prepend 'fio: pid=..., err=...' even in JSON mode.

    Accept only fio diagnostic lines before ONE complete JSON document.
    A broken/truncated report, a second report or arbitrary text is an error.
    Raw stdout and stderr remain in the result folder.
    """
    lines=text.lstrip('\ufeff').splitlines(keepends=True)
    prefix=[]
    for index,line in enumerate(lines):
        if line.lstrip().startswith('{'):
            break
        need(not line.strip() or line.startswith('fio: '),
             'Nieznany tekst przed raportem JSON fio; zachowano surowy wynik')
        prefix.append(line)
    else:
        raise RuntimeError('Brak kompletnego raportu JSON fio')
    try:
        obj=json.loads(''.join(lines[index:]))
    except json.JSONDecodeError as exc:
        raise RuntimeError('Uszkodzony lub niejednoznaczny raport JSON fio: '+str(exc)) from exc
    need(isinstance(obj,dict) and str(obj.get('fio version','')).startswith('fio-3.')
         and isinstance(obj.get('jobs'),list) and bool(obj['jobs'])
         and all(isinstance(job,dict) for job in obj['jobs']),
         'Nieprawidłowa struktura raportu fio3.x')
    return obj,''.join(prefix).strip()

def load_fio(path,emit):
    obj,prefix=parse_fio(path.read_text(encoding='utf-8'))
    path.with_name(path.stem+'-parsed.json').write_text(json.dumps(obj,indent=2),encoding='utf-8')
    if prefix:emit(stage='fio_output_diagnostics',file=path.name,text=prefix)
    return obj

def check_expected_failure(obj,rc,stderr,size):
    """A deliberate mismatch must give Linux EILSEQ (84), not an I/O error.

    Used ONLY for the private host regular file, never to accept an SSD error.
    """
    jobs=obj.get('jobs',[]);expected=plan(size)
    need(rc>0 and len(jobs)==len(expected),'Brak oczekiwanego wyniku kontrolnej weryfikacji')
    for job,(name,offset,length,bs) in zip(jobs,expected):
        need(job.get('jobname')==name and job.get('error') in (0,84),
             'Kontrola fio: wystąpił inny błąd niż oczekiwane EILSEQ')
        need(job.get('write',{}).get('io_bytes',0)==0 and job.get('trim',{}).get('io_bytes',0)==0,
             'Kontrolny odczyt wykonał zapis lub trim')
    need(any(j.get('error')==84 and j.get('read',{}).get('io_bytes',0)>0 for j in jobs)
         and 'pattern: verify failed at file ' in stderr and 'fio: got pattern ' in stderr,
         'Brak potwierdzenia wykrycia kontrolnej niezgodności wzorca')

def check_fio(obj,size,mode):
    jobs=obj.get('jobs',[]);expected=plan(size)
    need(len(jobs)==len(expected),'Nieprawidłowa liczba zadań fio')
    direction='write' if mode=='write' else 'read'
    for job,(name,offset,length,bs) in zip(jobs,expected):
        need(job.get('jobname')==name and job.get('error')==0,'Błąd zadania fio '+name)
        need(job.get(direction,{}).get('io_bytes')==length,'Niepełny transfer fio '+name)
        need(job.get('read' if mode=='write' else 'write',{}).get('io_bytes',0)==0,
             'Nieoczekiwany kierunek I/O')
        need(job.get('trim',{}).get('io_bytes',0)==0,'Nieoczekiwany trim w teście fio')
    return sum(job[direction]['io_bytes'] for job in jobs)

def run_fio(folder,device,size,mode,pattern,tag,emit):
    config=folder/(tag+'.fio');output=folder/(tag+'.json');errors=folder/(tag+'-stderr.txt')
    config.write_text(job_text(device,size,mode,pattern),encoding='utf-8')
    command=['fio','--output-format=json','--eta=never','--exitall_on_error=1']
    if mode=='verify':command+=['--readonly']
    command+=[str(config)]
    emit(stage='fio_start',mode=mode,bytes=size,command=command)
    with output.open('wb') as stdout,errors.open('wb') as stderr:
        process=sp.Popen(command,stdout=stdout,stderr=stderr,cwd=folder)
        started=time.monotonic()
        try:
            while process.poll() is None:
                try:process.wait(timeout=30)
                except sp.TimeoutExpired:emit(stage='fio_wait',mode=mode,seconds=int(time.monotonic()-started))
        except BaseException:
            process.terminate()
            try:process.wait(timeout=10)
            except sp.TimeoutExpired:process.kill();process.wait()
            raise
    emit(stage='fio_end',mode=mode,returncode=process.returncode)
    return process.returncode,output

def smoke(folder,emit):
    """Exercise installed fio on an 8MiB host REGULAR FILE before touching SSD data."""
    sample=folder/'fio-sanity-regular-file.bin';size=7*MIB+352256;pattern=secrets.token_hex(16)
    with sample.open('xb') as f:f.truncate(size)
    need(stat.S_ISREG(sample.stat().st_mode),'Sanity test wymaga zwykłego pliku')
    try:
        for mode in ('write','verify'):
            rc,out=run_fio(folder,sample,size,mode,pattern,'sanity-'+mode,emit)
            need(rc==0,'Test fio na zwykłym pliku nie przeszedł; bez zapisu CX400')
            check_fio(load_fio(out,emit),size,mode)
        rc,out=run_fio(folder,sample,size,'verify',secrets.token_hex(16),'sanity-wrong-pattern-EXPECTED',emit)
        check_expected_failure(load_fio(out,emit),rc,
                               (folder/'sanity-wrong-pattern-EXPECTED-stderr.txt').read_text(encoding='utf-8'),size)
        emit(stage='fio_expected_mismatch_detected',test='wrong_pattern',note='Private host regular file only')
        with sample.open('r+b') as f:
            f.seek(100);old=f.read(1);f.seek(100);f.write(bytes([old[0]^1]));f.flush();os.fsync(f.fileno())
        rc,out=run_fio(folder,sample,size,'verify',pattern,'sanity-corruption-EXPECTED',emit)
        check_expected_failure(load_fio(out,emit),rc,
                               (folder/'sanity-corruption-EXPECTED-stderr.txt').read_text(encoding='utf-8'),size)
        emit(stage='fio_expected_mismatch_detected',test='bit_flip',note='Private host regular file only')
        emit(stage='fio_sanity_pass',note='Good regular-file read accepted; deliberate corruption rejected')
    finally:sample.unlink()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('write','verify'))
    args=parser.parse_args()
    need(sys.platform.startswith('linux') and os.geteuid()==0,'Uruchom pod Linuxem przez sudo')
    import fcntl
    need(shutil.which('fio') and shutil.which('smartctl'),'Zainstaluj: sudo apt install fio smartmontools')
    root=Path(__file__).resolve().parent;state_path=root/'test-state.json'
    lock=(root/'test.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    stamp=dt.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')
    folder=root/('cx400-final-'+args.mode+'-result-'+stamp);folder.mkdir()
    records=[];monitor=None;monitor_out=None;monitor_err=None;status=1
    def emit(**fields):
        item=dict(time=dt.datetime.now().astimezone().isoformat(),**fields);records.append(item)
        print(json.dumps(item,ensure_ascii=True),flush=True)
    def command(argv,name):
        run=sp.run(argv,stdout=sp.PIPE,stderr=sp.PIPE,timeout=30)
        (folder/name).write_bytes(run.stdout)
        (folder/(name+'.stderr')).write_bytes(run.stderr)
        return run
    def discover():
        found=command(['lsblk','-b','-p','-J','-o','NAME,SIZE,MODEL,SERIAL,TRAN,TYPE,MOUNTPOINTS,RO'],'lsblk.json')
        need(found.returncode==0,'Nie udał się odczyt lsblk')
        disk,nodes=select_device(json.loads(found.stdout));device=Path(disk['name'])
        need(stat.S_ISBLK(device.stat().st_mode),'Cel nie jest urządzeniem blokowym')
        path=(Path('/sys/class/block')/device.name/'device').resolve(strict=True)
        need('usb' not in str(path) and re.search(r'/ata\d+/',str(path)),'Cel nie jest natywnym SATA')
        for node in nodes:
            holders=Path('/sys/class/block')/Path(node['name']).name/'holders'
            need(holders.is_dir() and not any(holders.iterdir()),'Dysk ma aktywnych użytkowników DM/RAID')
        swaps={str(Path(line.split()[0]).resolve()) for line in Path('/proc/swaps').read_text().splitlines()[1:]}
        need(not any(str(Path(n['name']).resolve()) in swaps for n in nodes),'Aktywny swap na CX400')
        return device,path
    def smart(device,label):
        result=command(['smartctl','-x','-j',str(device)],label+'.json')
        obj=check_smart(json.loads(result.stdout));return obj
    def save_state(obj):
        temp=root/'test-state.json.new'
        with temp.open('w',encoding='utf-8') as f:
            json.dump(obj,f,indent=2);f.flush();os.fsync(f.fileno())
        temp.replace(state_path)
        fd=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def stop_monitor():
        nonlocal monitor,monitor_out,monitor_err
        if monitor is not None:
            monitor.terminate()
            try:monitor.wait(timeout=5)
            except sp.TimeoutExpired:monitor.kill();monitor.wait()
            monitor=None
        if monitor_out is not None:monitor_out.close();monitor_out=None
        if monitor_err is not None:monitor_err.close();monitor_err=None
    try:
        emit(stage='package',version='cx400-final-test-2',mode=args.mode,
             script_sha256=digest(Path(__file__).read_bytes()))
        cmdline=Path('/proc/cmdline').read_text()
        (folder/'kernel-cmdline.txt').write_text(cmdline,encoding='utf-8')
        (folder/'kernel-version.txt').write_text(' '.join(os.uname())+'\n',encoding='utf-8')
        emit(stage='host_boot',cmdline=cmdline.strip())
        version=command(['fio','--version'],'fio-version.txt')
        need(version.returncode==0 and version.stdout.strip().startswith(b'fio-3.'),
             'Wymagane fio3.x (pakiet Debian fio), nie polecenie Fiona')
        device,path=discover();before=smart(device,'smart-before')
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        emit(stage='target',device=str(device),path=str(path),serial=SERIAL,
             bytes=CAPACITY,power_cycles=power_cycles(before))
        if args.mode=='write':
            need(not state_path.exists(),'Zapis był już uruchamiany; nie będzie powtórzony. Przekaż ZIP wyniku.')
            state=dict(version=2,status='PREPARING',serial=SERIAL,capacity=CAPACITY,firmware=FIRMWARE,
                       pattern=secrets.token_hex(16),write_boot_id=boot,
                       write_before_power_cycles=power_cycles(before))
            save_state(state)
            smoke(folder,emit)
        else:
            state=json.loads(state_path.read_text())
            verify_state(state,before,boot)
        first=(str(device),str(path));device,path=discover()
        need(first==(str(device),str(path)),'Zmiana urządzenia przed testem')
        check_smart(smart(device,'smart-immediate-before'))
        need('libata.force=4:1.5' not in Path('/proc/cmdline').read_text(),
             'Test końcowy uruchom bez wymuszenia1.5Gbps')
        monitor_out=(folder/'kernel-during.txt').open('wb')
        monitor_err=(folder/'kernel-monitor-stderr.txt').open('wb')
        monitor=sp.Popen(['dmesg','--follow-new','--time-format=raw'],stdout=monitor_out,stderr=monitor_err)
        time.sleep(0.2);need(monitor.poll() is None,'Brak działającego monitora kernela')
        if args.mode=='write':
            state.update(status='WRITE_IN_PROGRESS',write_result_folder=folder.name)
            save_state(state)
        rc,result_file=run_fio(folder,device,CAPACITY,args.mode,state['pattern'],'cx400-full',emit)
        need(rc==0,'fio zgłosiło błąd; STOP bez ponawiania')
        count=check_fio(load_fio(result_file,emit),CAPACITY,args.mode)
        need(monitor.poll() is None,'Monitor kernela zakończył się przed końcem testu')
        stop_monitor();after=smart(device,'smart-after')
        kernel=(folder/'kernel-during.txt').read_text(errors='replace')
        suspicious=re.findall(r'^.*(?:I/O error|Buffer I/O|failed command|hard resetting link|softreset failed|link is slow to respond|limiting SATA link speed|exception Emask|SError:).*$'
                              ,kernel,re.MULTILINE|re.IGNORECASE)
        if args.mode=='write':
            state.update(status='WRITE_COMPLETE',write_after_power_cycles=power_cycles(after),
                         write_fio_sha256=digest(result_file.read_bytes()),write_result_folder=folder.name,
                         kernel_warnings=suspicious)
            save_state(state)
            emit(result='WRITE_COMPLETE_POWER_CYCLE_REQUIRED',bytes=count,kernel_warnings=suspicious,
                 next='sudo poweroff; physically disconnect SSD power30s; reboot Linux; run verify from this same folder')
        else:
            emit(result='FULL_CAPACITY_COLD_READ_VERIFIED' if not suspicious and not state.get('kernel_warnings')
                 else 'DATA_VERIFIED_WITH_KERNEL_WARNINGS',bytes=count,header_crc32c=True,
                 unique_pattern_matched=True,kernel_warnings=suspicious,
                 write_power_cycles=state['write_after_power_cycles'],read_power_cycles=power_cycles(before))
        status=0
    except (Exception,KeyboardInterrupt) as exc:
        emit(result='STOP_WITHOUT_RETRY',error=str(exc))
    finally:
        stop_monitor()
        if state_path.is_file():shutil.copyfile(state_path,folder/'test-state-copy.json')
        (folder/'report.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
        archive=Path(str(folder)+'.zip')
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
            for p in sorted(folder.iterdir()):
                if p.is_file():z.write(p,p.name)
        print('RESULT ZIP: '+str(archive),flush=True)
        print('Po błędzie: przekaż ZIP; bez ponawiania zapisu.',flush=True)
        lock.close()
    return status

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:print('STOP przed testem: '+str(error),file=sys.stderr);sys.exit(2)
