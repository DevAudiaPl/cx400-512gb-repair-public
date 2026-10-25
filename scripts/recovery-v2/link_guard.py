from pathlib import Path
import re
REQUIRED_FORCE='libata.force=4:1.5Gbps'

def require_link(device, cmdline, link_class=Path('/sys/class/ata_link')):
    force = [token for token in cmdline.split() if token.startswith('libata.force=')]
    if force != [REQUIRED_FORCE]:
        raise RuntimeError('Wymagany jednorazowy start kernela z ' + REQUIRED_FORCE)
    ata_dirs = [p for p in (device,) + tuple(device.parents) if re.fullmatch(r'ata[1-9][0-9]*', p.name)]
    if len(ata_dirs) != 1 or ata_dirs[0].name != 'ata4':
        raise RuntimeError('Badany SSD nie jest na ata4; odmowa testu z limitem innego portu')
    ata_dir = ata_dirs[0]
    link = link_class/'link4'
    resolved = link.resolve(strict=True)
    if ata_dir not in (resolved,) + tuple(resolved.parents):
        raise RuntimeError('link4 nie nalezy do portu wybranego SSD')
    speed = ' '.join((link/'sata_spd').read_text().split())
    limit = ' '.join((link/'sata_spd_limit').read_text().split())
    if speed != '1.5 Gbps' or limit != '1.5 Gbps':
        raise RuntimeError('Niepotwierdzony limit SATA1.5: speed=' + speed + ', limit=' + limit)
    return dict(ata_port=4, link_path=str(resolved), negotiated_speed=speed, speed_limit=limit)
