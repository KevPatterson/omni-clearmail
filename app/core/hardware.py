"""Fingerprint del host para hardware binding (OMNI-Lic).

Obtiene hostname, MACs e IPs locales reales sin dependencias externas.
Usado por LIL para generar solicitudes y validar licencias.
"""
import hashlib
import platform
import re
import socket
import subprocess
import uuid


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def get_local_ips() -> list:
    ips = set()
    try:
        hostname = get_hostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no envia trafico real
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    for ip in ips:
        if not ip.startswith("127.") and not ip.startswith("0."):
            return sorted(ips)
    return sorted(ips) if ips else ["127.0.0.1"]


def get_macs() -> list:
    macs = set()
    mac = uuid.getnode()
    if mac is not None and (mac >> 40) & 1 == 0:  # no randomizado
        macs.add(":".join(f"{(mac >> i) & 0xFF:02x}" for i in range(40, -1, -8)))
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(
                "getmac", shell=True, text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                m = re.search(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", line)
                if m:
                    macs.add(m.group(0).replace("-", ":"))
        elif system in ("linux", "darwin"):
            out = subprocess.check_output(
                "ifconfig -a", shell=True, text=True, stderr=subprocess.DEVNULL
            )
            for m in re.finditer(r"(?:ether|HWaddr)\s+([0-9A-Fa-f:]{17})", out):
                macs.add(m.group(1))
    except Exception:
        pass
    return sorted(macs) if macs else ["00:00:00:00:00:00"]


def hardware_fingerprint() -> dict:
    """Binding real del host: hostname, MACs e IPs por componente."""
    ip_local = get_local_ips()
    return {
        "ip": ip_local[0] if ip_local else "127.0.0.1",
        "ip_local": ip_local,
        "hostname": get_hostname(),
        "macs": get_macs(),
    }


def identity_sistema(nombre_software="Omni-CleanerMail") -> str:
    """Slug identidad del software para OMNI-Lic (espacios/_ -> -, minusculas, sin acentos)."""
    import unicodedata

    s = unicodedata.normalize("NFKD", nombre_software)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.replace(" ", "-").replace("_", "-")
    s = re.sub(r"[^a-zA-Z0-9-]", "", s)
    return s.lower()