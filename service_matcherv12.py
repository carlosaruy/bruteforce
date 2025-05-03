"""service_matcher.py

Compara los servicios detectados en uno o más archivos de salida de Nmap
(XML `-oX` o texto normal `-oN`) con la lista de *servicios soportados* por
Herramientas como Hydra/Medusa.

Características clave
---------------------
* Alias Map construido en tiempo de carga (O(1) look‑up)
* Acepta varios archivos Nmap a la vez
* Salida opcional en JSON (`--json`)
* Informa coincidencias y servicios no soportados
* Sin dependencias externas (solo stdlib)

Para colaborar, edita el diccionario `SERVICE_SYNONYMS` y envía un PR.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Set

# --------------------------- ALIAS DICTIONARY --------------------------- #
# Diccionario comunitario: servicio base → alias que Nmap puede mostrar
SERVICE_SYNONYMS: Dict[str, List[str]] = {
    "adam6500": ["adam6500"],
    "asterisk": ["asterisk"],
    "cobaltstrike": ["unknown"],
    "cvs": ["cvspserver"],
    "firebird": ["gds_db"],
    "ftp": ["ftp"],
    "ftps": ["ftps"],
    "http-get": ["http", "http-alt"],
    "http-head": ["http", "http-alt"],
    "http-post": ["http", "http-alt"],
    "https-get": ["https", "ssl/http", "https-alt"],
    "https-head": ["https", "ssl/http", "https-alt"],
    "https-post": ["https", "ssl/http", "https-alt"],
    "http-get-form": ["http", "http-alt"],
    "http-post-form": ["http", "http-alt"],
    "https-get-form": ["https", "ssl/http", "https-alt"],
    "https-post-form": ["https", "ssl/http", "https-alt"],
    "http-proxy": ["http-proxy"],
    "http-proxy-urlenum": ["http-proxy"],
    "icq": ["aol"],
    "imap": ["imap", "imaps"],
    "irc": ["irc"],
    "ldap2": ["ldap", "ldapssl"],
    "ldap3": ["ldap", "ldapssl"],
    "memcached": ["memcache"],
    "mongodb": ["mongodb", "mongod"],
    "mssql": ["ms-sql-s"],
    "mysql": ["mysql"],
    "nntp": ["nntp"],
    "oracle-listener": ["oracle-tns", "oracle"],
    "oracle-sid": ["oracle-tns", "oracle"],
    "pcanywhere": ["pcanywheredata", "pcanywherestat"],
    "pcnfs": ["pcnfs"],
    "pop3": ["pop3", "pop3s"],
    "postgres": ["postgresql"],
    "radmin2": ["radmin"],
    "rdp": ["ms-wbt-server"],
    "redis": ["redis"],
    "rexec": ["exec"],
    "rlogin": ["login"],
    "rpcap": ["globe"],
    "rsh": ["shell"],
    "rtsp": ["rtsp", "rtsp-alt"],
    "s7-300": ["iso-tsap"],
    "sip": ["sip", "sip-tls"],
    "smb": ["microsoft-ds", "netbios-ssn"],
    "smtp": ["smtp", "submission", "smtps", "ssl/smtp"],
    "smtp-enum": ["smtp", "submission", "smtps"],
    "snmp": ["snmp"],
    "socks5": ["socks"],
    "ssh": ["ssh"],
    "sshkey": ["ssh"],
    "svn": ["svnserve"],
    "teamspeak": ["teamspeak", "teamspeak-serverquery"],
    "telnet": ["telnet", "telnets"],
    "vmauthd": ["vmware-auth", "ssl/vmware-auth", "iss-realsecure"],
    "vnc": ["vnc", "vnc-1", "vnc-2", "vnc-3"],
    "xmpp": ["xmpp-client", "jabber", "ssl/xmpp", "ssl/jabber"],
}

# Construimos alias → base para búsqueda rápida
ALIAS_TO_BASE: Dict[str, str] = {
    alias: base for base, aliases in SERVICE_SYNONYMS.items() for alias in aliases
}

# ---------------------------- REGEX & CONST ----------------------------- #
_PORT_OPEN_RE = re.compile(r"\b\d+/tcp\s+open\s+(?P<svc>\S+)")

# --------------------------- FILE PARSERS ------------------------------- #

def load_supported_bases(path: Path) -> Set[str]:
    """Extrae los servicios base soportados del fichero proporcionado."""
    text = path.read_text(encoding="utf-8").strip()
    if ":" in text:
        text = text.split(":", 1)[1]
    return {
        re.match(r"^([^\[\{\-]+)", token).group(1)
        for token in text.split()
        if token
    }


def parse_nmap_xml(path: Path) -> Set[str]:
    services: Set[str] = set()
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        sys.exit(f"[!] Error al parsear XML '{path}': {exc}")
    for port in tree.findall(".//port[@protocol='tcp']"):
        svc = port.find("service")
        if svc is not None and svc.get("name"):
            services.add(svc.get("name"))
    return services


def parse_nmap_normal(path: Path) -> Set[str]:
    services: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if (m := _PORT_OPEN_RE.search(line)):
            services.add(m.group("svc").rstrip("?"))
    return services


# --------------------------- CORE FUNCTIONS ----------------------------- #

def normalize_service(svc: str, supported: Set[str]) -> str | None:
    """Convierte el nombre detectado en su base soportada si existe."""
    if svc in supported:
        return svc
    base = ALIAS_TO_BASE.get(svc)
    return base if base in supported else None


def gather_services(paths: Iterable[Path]) -> Set[str]:
    detected: Set[str] = set()
    for p in paths:
        detected |= parse_nmap_xml(p) if p.suffix.lower() == ".xml" else parse_nmap_normal(p)
    return detected


# ------------------------------ CLI ------------------------------------- #

def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Compara servicios detectados por Nmap con servicios soportados.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("supported_file", type=Path, help="Fichero con la línea 'Supported services: ...'")
    ap.add_argument("nmap_files", nargs="+", type=Path, help="Uno o más ficheros de salida Nmap (.xml o .nmap)")
    ap.add_argument("--json", action="store_true", help="Salida en formato JSON")
    return ap


def main() -> None:
    args = build_argparser().parse_args()
    if not args.supported_file.exists():
        sys.exit(f"[!] Archivo no encontrado: {args.supported_file}")

    supported = load_supported_bases(args.supported_file)
    scanned = gather_services(args.nmap_files)

    matched = {normalize_service(s, supported) for s in scanned if normalize_service(s, supported)}
    unmatched = scanned - {s for s in scanned if normalize_service(s, supported)}

    if args.json:
        json_output = {
            "detected": sorted(scanned),
            "matched": sorted(matched),
            "unmatched": sorted(unmatched),
        }
        print(json.dumps(json_output, indent=2, ensure_ascii=False))
        return

    # Salida en texto
    print("Servicios detectados:")
    for s in sorted(scanned):
        print(f" - {s}")

    print("\nServicios soportados coincidentes:")
    if matched:
        for s in sorted(matched):
            print(f" * {s}")
    else:
        print("  Ninguno")

    if unmatched:
        print("\nServicios NO soportados encontrados:")
        for s in sorted(unmatched):
            print(f" - {s}")


if __name__ == "__main__":
    main()
