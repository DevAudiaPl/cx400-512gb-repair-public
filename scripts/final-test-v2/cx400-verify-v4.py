#!/usr/bin/env python3
"""Read-only cold verification of the completed CX400 write from 2026-10-25.

Place next to the ORIGINAL cx400-test.py v2 and its test-state.json.
This entry has no write mode. It never calls the original main/smoke/run_fio.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess as sp
import sys
import time
import zipfile

CORE_SHA='1acc7ab9fcfe93495a89f293fb0e6b1e22d5eb07efbedb2c160aff3a6e1ca95c'
WRITE_SHA='c549af45679d750193ea3ba4fe5d142ba3945cd7306b457b726ace528bbff33e'
WRITE_FOLDER='cx400-final-write-result-20261025-003327'
SERIAL='CX4R2610242000213B51'
CAPACITY=512110190592

def need(ok,message):
    if not ok:raise RuntimeError(message)

def sha(data):return hashlib.sha256(data).hexdigest()

def load_core(root):
    source=root/'cx400-test.py'
    need(source.is_file() and sha(source.read_bytes())==CORE_SHA,
         'Brak oryginalnego cx400-test.py v2. Umieść ten plik w istniejącym katalogu cx400-final-test-v2.')
    spec=importlib.util.spec_from_file_location('cx400_readonly_core',source)
    core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
    return core

def check_environment(cmdline,smart):
    tokens=cmdline.split()
    limits=[token for token in tokens if token.startswith('libata.force=')]
    need(limits==['libata.force=4:1.5Gbps'] and 'pci=nomsi' in tokens,
         'Uruchom Linux z pci=nomsi libata.force=4:1.5Gbps (bez spacji w 1.5Gbps).')
    need(smart.get('interface_speed',{}).get('current',{}).get('sata_value')==1,
         'SMART nie potwierdza rzeczywistego połączenia SATA 1.5Gb/s.')

def check_write_proof(root,state,core):
    need(state.get('status')=='WRITE_COMPLETE' and state.get('write_result_folder')==WRITE_FOLDER
         and state.get('write_fio_sha256')==WRITE_SHA,
         'Brak potwierdzonego pełnego zapisu 003327. Zachowaj pliki; nie powtarzaj zapisu.')
    path=root/WRITE_FOLDER/'cx400-full.json'
    need(path.is_file() and sha(path.read_bytes())==WRITE_SHA,
         'Brak oryginalnego wyniku pełnego zapisu w tym katalogu.')
    report,prefix=core.parse_fio(path.read_text(encoding='utf-8'))
    need(not prefix and core.check_fio(report,CAPACITY,'write')==CAPACITY,'Nieprawidłowy wynik poprzedniego zapisu.')
    need(report.get('global options',{}).get('verify_pattern')=='0x'+state.get('pattern',''),
         'Wzorzec w stanie nie zgadza się ze wzorcem rzeczywistego zapisu.')

def smart_counters(obj):
    attrs={a['id']:a.get('raw',{}).get('value') for a in obj.get('ata_smart_attributes',{}).get('table',[])}
    pages={row['name']:row['value'] for page in obj.get('ata_device_statistics',{}).get('pages',[]) for row in page.get('table',[])}
    return {'SATA_PHY':attrs.get(168),'CRC':attrs.get(218),'Bad_Blk_Ct_Lat/Erl_raw':attrs.get(170),
            'Reported_Uncorrectable':pages.get('Number of Reported Uncorrectable Errors')}

def read_stat_bytes(text):
    fields=text.split()
    need(len(fields)>=11,'Nieprawidłowy licznik sysfs stat')
    return int(fields[2])*512

def fio_command(config):
    return ['fio','--readonly','--output-format=json','--eta=never','--exitall_on_error=1',str(config)]

def duration(seconds):
    if seconds is None:return '--:--:--'
    hours,left=divmod(max(0,math.ceil(seconds)),3600)
    minutes,secs=divmod(left,60)
    return f'{hours:02d}:{minutes:02d}:{secs:02d}'

def progress_fields(read_bytes,speed,counter_valid):
    if not counter_valid or read_bytes is None:
        return dict(progress_percent=None,remaining_bytes=None,eta_seconds=None)
    remaining=max(0,CAPACITY-max(0,read_bytes))
    percent=min(100.0,max(0.0,read_bytes/CAPACITY*100))
    usable_speed=isinstance(speed,(int,float)) and math.isfinite(speed) and speed>0
    eta=0 if remaining==0 else math.ceil(remaining/(speed*1e6)) if usable_speed else None
    return dict(progress_percent=percent,remaining_bytes=remaining,eta_seconds=eta)

def progress_line(item):
    elapsed=duration(item['seconds']);percent=item['progress_percent']
    if percent is None:
        return f'Odczyt [????????????????????????] postep niedostepny (reset licznika) | czas {elapsed}'
    filled=min(24,int(percent/100*24))
    bar='#'*filled+'-'*(24-filled)
    read_gb=item['read_since_start_bytes']/1e9
    speed=item['recent_MBps']
    speed_text=f'{speed:.1f} MB/s' if isinstance(speed,(int,float)) and math.isfinite(speed) and speed>=0 else '-- MB/s'
    line=(f'Odczyt [{bar}] {percent:5.1f}% | {read_gb:.2f} / {CAPACITY/1e9:.2f} GB'
          f' | {speed_text} | pozostalo ~{duration(item["eta_seconds"])} | czas {elapsed}')
    if percent>=100:line+=' | oczekiwanie na wynik weryfikacji'
    elif item['seconds']==0 and item['read_since_start_bytes']==0:line+=' | pierwszy pomiar za 30 s'
    elif not speed:line+=' | brak odczytu w ostatnim pomiarze'
    return line

def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    need(sys.platform.startswith('linux') and os.geteuid()==0,'Uruchom pod Linuxem przez sudo.')
    need(shutil.which('fio') and shutil.which('smartctl'),'Wymagane fio i smartmontools.')
    import fcntl
    root=Path(__file__).resolve().parent
    core=load_core(root)
    lock=(root/'test.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    folder=root/('cx400-final-verify-result-'+dt.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S'))
    folder.mkdir()
    records=[];monitor=None;monitor_out=None;monitor_err=None;result_code=1
    def emit(**fields):
        record=dict(time=dt.datetime.now().astimezone().isoformat(),**fields)
        records.append(record)
        print(progress_line(record) if record.get('stage')=='fio_wait'
              else json.dumps(record,ensure_ascii=True),flush=True)
    def command(argv,label):
        run=sp.run(argv,stdout=sp.PIPE,stderr=sp.PIPE,timeout=30)
        (folder/label).write_bytes(run.stdout);(folder/(label+'.stderr')).write_bytes(run.stderr)
        return run
    def discover():
        run=command(['lsblk','-b','-p','-J','-o','NAME,SIZE,MODEL,SERIAL,TRAN,TYPE,MOUNTPOINTS,RO'],'lsblk.json')
        need(run.returncode==0,'Błąd lsblk.')
        disk,nodes=core.select_device(json.loads(run.stdout));device=Path(disk['name'])
        need(stat.S_ISBLK(device.stat().st_mode),'Cel nie jest urządzeniem blokowym.')
        path=(Path('/sys/class/block')/device.name/'device').resolve(strict=True)
        need('usb' not in str(path) and re.search(r'/ata\d+/',str(path)),'Wymagane natywne SATA.')
        for node in nodes:
            holders=Path('/sys/class/block')/Path(node['name']).name/'holders'
            need(holders.is_dir() and not any(holders.iterdir()),'Aktywne mapowanie DM/RAID.')
        swaps={str(Path(line.split()[0]).resolve()) for line in Path('/proc/swaps').read_text().splitlines()[1:]}
        need(not any(str(Path(n['name']).resolve()) in swaps for n in nodes),'Aktywny swap na CX400.')
        return device,path
    def smart(device,label):
        run=command(['smartctl','-x','-j',str(device)],label+'.json')
        return core.check_smart(json.loads(run.stdout))
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
        emit(stage='package',version='cx400-cold-verify-4',mode='verify',script_sha256=sha(Path(__file__).read_bytes()))
        cmdline=Path('/proc/cmdline').read_text();(folder/'kernel-cmdline.txt').write_text(cmdline,encoding='utf-8')
        (folder/'kernel-version.txt').write_text(' '.join(os.uname())+'\n',encoding='utf-8')
        emit(stage='host_boot',cmdline=cmdline.strip())
        version=command(['fio','--version'],'fio-version.txt')
        need(version.returncode==0 and version.stdout.strip().startswith(b'fio-3.'),'Wymagane fio3.x.')
        state=json.loads((root/'test-state.json').read_text())
        check_write_proof(root,state,core)
        device,path=discover();before=smart(device,'smart-before')
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        core.verify_state(state,before,boot)
        check_environment(cmdline,before)
        emit(stage='target',device=str(device),path=str(path),serial=SERIAL,bytes=CAPACITY,
             power_cycles=core.power_cycles(before),sata_speed='1.5 Gb/s',mode='read-only')
        first=(str(device),str(path));device,path=discover()
        need(first==(str(device),str(path)),'Urządzenie zmieniło się przed odczytem.')
        immediate=smart(device,'smart-immediate-before');check_environment(cmdline,immediate)
        config=folder/'cx400-full.fio';raw_output=folder/'cx400-full.json'
        config.write_text(core.job_text(device,CAPACITY,'verify',state['pattern']),encoding='utf-8')
        monitor_out=(folder/'kernel-during.txt').open('wb');monitor_err=(folder/'kernel-monitor-stderr.txt').open('wb')
        monitor=sp.Popen(['dmesg','--follow-new','--time-format=raw'],stdout=monitor_out,stderr=monitor_err)
        time.sleep(0.2);need(monitor.poll() is None,'Monitor kernela nie działa.')
        counter=Path('/sys/class/block')/device.name/'stat'
        start_bytes=last_bytes=read_stat_bytes(counter.read_text());counter_valid=True
        started=last_time=time.monotonic()
        argv=fio_command(config)
        emit(stage='fio_start',mode='verify',bytes=CAPACITY,command=argv)
        emit(stage='fio_wait',mode='verify',seconds=0,read_since_start_bytes=0,
             recent_MBps=0.0,counter_valid=True,**progress_fields(0,0.0,True))
        with raw_output.open('wb') as output,(folder/'cx400-full-stderr.txt').open('wb') as errors:
            process=sp.Popen(argv,stdout=output,stderr=errors,cwd=folder)
            try:
                while process.poll() is None:
                    try:process.wait(timeout=30)
                    except sp.TimeoutExpired:
                        now=time.monotonic();current=read_stat_bytes(counter.read_text())
                        if current<last_bytes:counter_valid=False
                        transferred=max(0,current-start_bytes) if counter_valid else None
                        speed=(current-last_bytes)/(now-last_time)/1e6 if counter_valid else None
                        emit(stage='fio_wait',mode='verify',seconds=int(now-started),
                             read_since_start_bytes=transferred,recent_MBps=speed,
                             counter_valid=counter_valid,**progress_fields(transferred,speed,counter_valid))
                        last_bytes,last_time=current,now
            except BaseException:
                process.terminate()
                try:process.wait(timeout=10)
                except sp.TimeoutExpired:process.kill();process.wait()
                raise
        emit(stage='fio_end',mode='verify',returncode=process.returncode)
        need(process.returncode==0,'fio zgłosiło błąd. Zachowaj ZIP, bez ponawiania zapisu.')
        data,prefix=core.parse_fio(raw_output.read_text(encoding='utf-8'))
        (folder/'cx400-full-parsed.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
        if prefix:emit(stage='fio_output_diagnostics',text=prefix)
        count=core.check_fio(data,CAPACITY,'verify')
        need(monitor.poll() is None,'Monitor kernela zakończył się przed końcem odczytu.')
        after=smart(device,'smart-after');stop_monitor()
        kernel=(folder/'kernel-during.txt').read_text(errors='replace')
        warnings=re.findall(r'^.*(?:I/O error|Buffer I/O|failed command|hard resetting link|softreset failed|link is slow to respond|limiting SATA link speed|exception Emask|SError:).*$',kernel,re.MULTILINE|re.IGNORECASE)
        a,b=smart_counters(immediate),smart_counters(after)
        changes={k:dict(before=a[k],after=b[k]) for k in a if a[k]!=b[k]}
        previous=state.get('kernel_warnings',[])
        emit(result='DATA_VERIFIED_WITH_KERNEL_WARNINGS' if warnings or previous or changes else 'FULL_CAPACITY_COLD_READ_VERIFIED',
             bytes=count,unique_pattern_matched=True,header_crc32c=True,
             write_power_cycles=state['write_after_power_cycles'],read_power_cycles=core.power_cycles(before),
             kernel_warnings=warnings,write_kernel_warnings=previous,smart_counter_changes=changes,
             read_sata_speed=after.get('interface_speed',{}).get('current'),
             next='Przekaż ZIP do oceny. Zachowaj zakończony zapis i jego stan.')
        result_code=0
    except (Exception,KeyboardInterrupt) as exc:
        emit(result='STOP_WITHOUT_RETRY',error=str(exc))
    finally:
        stop_monitor()
        if (root/'test-state.json').is_file():shutil.copyfile(root/'test-state.json',folder/'test-state-copy.json')
        (folder/'report.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
        archive=Path(str(folder)+'.zip')
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
            for p in sorted(folder.iterdir()):
                if p.is_file():z.write(p,p.name)
        print('RESULT ZIP: '+str(archive),flush=True);lock.close()
    return result_code

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:print('STOP przed odczytem: '+str(error),file=sys.stderr);sys.exit(2)
