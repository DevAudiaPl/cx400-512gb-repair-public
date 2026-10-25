"""A private ftrace instance, filtered to the selected ATA port.

No global tracing switches, disk operations or kernel module changes.
May mount tracefs in the result directory if it is not already mounted.
"""
from pathlib import Path
import re
import subprocess
import uuid


REQUIRED_EVENTS = ('ata_qc_issue', 'ata_qc_complete_failed',
                   'ata_eh_link_autopsy', 'ata_eh_link_autopsy_qc')
OPTIONAL_EVENTS = ('ata_qc_prep', 'ata_qc_complete_done', 'ata_qc_complete_internal',
                   'ata_eh_about_to_do', 'ata_eh_done',
                   'ata_link_hardreset_begin', 'ata_link_hardreset_end',
                   'ata_link_softreset_begin', 'ata_link_softreset_end')


def port_from_device(device):
    matches = [int(p.name[3:]) for p in (device,) + tuple(device.parents)
               if re.fullmatch(r'ata[1-9][0-9]*', p.name)]
    if len(matches) != 1:
        raise RuntimeError('Nie mozna jednoznacznie wyznaczyc portu ATA dla trace')
    return matches[0]


class Capture:
    def __init__(self, device, folder, emit, roots=None):
        self.port = port_from_device(device)
        self.folder = folder
        self.emit = emit
        self.roots = roots if roots is not None else (
            Path('/sys/kernel/tracing'), Path('/sys/kernel/debug/tracing'))
        self.instance = None
        self.mountpoint = None
        self.enabled = []
        self.started = False

    def start(self):
        root = next((p for p in self.roots
                     if (p/'events/libata').is_dir() and (p/'instances').is_dir()), None)
        if root is None:
            self.mountpoint = self.folder/'tracefs-mount'
            self.mountpoint.mkdir()
            result = subprocess.run(['mount', '-t', 'tracefs', 'tracefs', str(self.mountpoint)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if result.returncode:
                self.mountpoint.rmdir()
                self.mountpoint = None
                raise RuntimeError('Nie udalo sie zamontowac tracefs: ' + result.stderr.decode(errors='replace'))
            root = self.mountpoint
        if not (root/'events/libata').is_dir() or not (root/'instances').is_dir():
            raise RuntimeError('Brak zdarzen libata albo prywatnych instancji tracefs')
        for event in REQUIRED_EVENTS:
            if not (root/'events/libata'/event/'format').is_file():
                raise RuntimeError('Brak wymaganego tracepointu: ' + event)
        instance = root/'instances'/('cx400-' + uuid.uuid4().hex)
        # Never reuse or clear an existing trace instance.
        instance.mkdir()
        self.instance = instance
        (instance/'tracing_on').write_text('0\n')
        (instance/'buffer_size_kb').write_text('128\n')
        if (instance/'trace_clock').exists():
            clocks = (instance/'trace_clock').read_text().replace('[','').replace(']','').split()
            if 'mono' in clocks:
                (instance/'trace_clock').write_text('mono\n')
        metadata = []
        for event in REQUIRED_EVENTS + OPTIONAL_EVENTS:
            base = instance/'events/libata'/event
            if not (base/'format').is_file():
                if event in REQUIRED_EVENTS:
                    raise RuntimeError('Tracepoint niedostepny w instancji: ' + event)
                continue
            fmt = (base/'format').read_text()
            if not re.search(r'field:[^;]*\bata_port\s*;', fmt):
                raise RuntimeError('Brak pola ata_port w tracepoincie: ' + event)
            expression = 'ata_port == ' + str(self.port)
            (base/'filter').write_text(expression + '\n')
            applied = (base/'filter').read_text().strip()
            if applied != expression:
                raise RuntimeError('Nie przyjeto filtra tracepointu: ' + event)
            (base/'enable').write_text('1\n')
            self.enabled.append(base)
            metadata.append('EVENT ' + event + '\nFILTER ' + applied + '\n' + fmt)
        (self.folder/'trace-formats.txt').write_text('\n\n'.join(metadata), encoding='utf-8')
        (instance/'tracing_on').write_text('1\n')
        self.started = True
        self.emit(stage='kernel_trace_started', ata_port=self.port, instance=str(instance),
                  events=[p.name for p in self.enabled])

    def close(self):
        instance = self.instance
        if instance is not None:
            try:
                (instance/'tracing_on').write_text('0\n')
                trace = (instance/'trace').read_text(errors='replace')
                (self.folder/'kernel-trace.txt').write_text(trace, encoding='utf-8')
                statistics = []
                for stat_file in sorted((instance/'per_cpu').glob('cpu*/stats')):
                    statistics.append(str(stat_file.relative_to(instance)) + '\n' + stat_file.read_text())
                (self.folder/'trace-statistics.txt').write_text('\n'.join(statistics), encoding='utf-8')
                self.emit(stage='kernel_trace_saved', bytes=len(trace.encode('utf-8')),
                          ata_port=self.port)
            except Exception as exc:
                self.emit(trace_capture_error=str(exc))
            finally:
                for base in self.enabled:
                    try:
                        (base/'enable').write_text('0\n')
                    except OSError as exc:
                        self.emit(trace_disable_error=str(exc))
                try:
                    # tracefs removes its virtual files when the instance is removed.
                    # No recursive filesystem deletion is used.
                    instance.rmdir()
                    self.instance = None
                except OSError as exc:
                    self.emit(trace_instance_cleanup_error=str(exc))
        if self.mountpoint is not None:
            try:
                result = subprocess.run(['umount', str(self.mountpoint)], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=10)
                if result.returncode:
                    self.emit(trace_unmount_error=result.stderr.decode(errors='replace'))
                else:
                    self.mountpoint.rmdir()
                    self.mountpoint = None
            except Exception as exc:
                self.emit(trace_unmount_error=str(exc))
