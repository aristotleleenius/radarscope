#!/usr/bin/env python3
"""Surveillance réseau locale pour macOS, basée sur nmap, arp et tcpdump."""

from __future__ import annotations

import argparse
import csv
import io
import json
import ipaddress
import os
import platform
import re
import shlex
import shutil
import signal
import sqlite3
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import parse_qs, urlparse


VERSION = "2.2.0"
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_PORTS = "22,80,443,631,8080"
DEFAULT_SUSPICIOUS_PORTS = "21,23,139,445,3389,5900,6379,27017"
DEFAULT_CAPTURE_FILTER = "tcp or arp or icmp or icmp6"
DEFAULT_TCPDUMP_BUFFER_KIB = 4096
DEFAULT_STATE_FILE = "radarscope_state.json"
DEFAULT_EVENT_LOG = "radarscope_events.jsonl"
DEFAULT_ARP_INTERVAL = 10.0
DEFAULT_SCAN_INTERVAL = 30.0
DEFAULT_CONFIRMATIONS = 2
DEFAULT_ALERT_COOLDOWN = 120.0
DEFAULT_SCAN_WINDOW = 10.0
DEFAULT_SCAN_PORT_THRESHOLD = 20
DEFAULT_SCAN_HOST_THRESHOLD = 10
DEFAULT_STEALTH_THRESHOLD = 5
DEFAULT_DASHBOARD_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 8765
DEFAULT_SNAPSHOT_LIMIT = 200
DEFAULT_HISTORY_FILE = "radarscope_history.sqlite3"
DEFAULT_HISTORY_INTERVAL = 10.0
DEFAULT_HISTORY_HOURS = 24.0
PUBLIC_IP_ENDPOINT = "https://api.ipify.org"
PUBLIC_IP_CACHE_TTL = 300.0
PUBLIC_IP_FAILURE_TTL = 30.0

_public_ip_cache_lock = threading.Lock()
_public_ip_cache: tuple[float, Optional[str]] = (0.0, None)


class Palette:
    """Couleurs ANSI truecolor, désactivables pour les redirections de sortie."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    def __init__(self, mode: str) -> None:
        enabled = mode == "always" or (mode == "auto" and sys.stdout.isatty())
        self.enabled = enabled

    def color(self, text: str, rgb: tuple[int, int, int], bold: bool = False) -> str:
        if not self.enabled:
            return text
        prefix = f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"
        if bold:
            prefix = self.BOLD + prefix
        return f"{prefix}{text}{self.RESET}"

    def header(self, text: str) -> str:
        return self.color(text, (80, 210, 255), bold=True)

    def info(self, text: str) -> str:
        return self.color(text, (170, 205, 255))

    def ok(self, text: str) -> str:
        return self.color(text, (100, 230, 140))

    def warn(self, text: str) -> str:
        return self.color(text, (255, 210, 80), bold=True)

    def suspect(self, text: str) -> str:
        return self.color(text, (255, 55, 55), bold=True)

    def dim(self, text: str) -> str:
        return self.color(text, (145, 155, 170))


def compact_nmap_line(line: str) -> str:
    report = NMAP_REPORT_RE.search(line) if "NMAP_REPORT_RE" in globals() else None
    if report:
        return f"HOST    {report.group(1).strip()}"
    port = NMAP_OPEN_RE.search(line) if "NMAP_OPEN_RE" in globals() else None
    if port:
        details = line[port.end():].strip()
        return f"OPEN    {port.group(1)}/{port.group(2).lower()} {details}".rstrip()
    if "Host is up" in line:
        return f"UP      {line.strip()}"
    if line.startswith("Nmap done:"):
        return f"DONE    {line.removeprefix('Nmap done:').strip()}"
    if "Stats:" in line or "About " in line:
        return f"PROGRESS {line.strip()}"
    return line


def compact_arp_line(line: str) -> str:
    match = ARP_LINE_RE.search(line) if "ARP_LINE_RE" in globals() else None
    if match:
        ip = match.group("ip").strip()
        mac = normalise_mac(match.group("mac"))
        interface = match.group("interface")
        if "incomplete" in mac:
            return f"INCOMPLETE ip={ip} iface={interface}"
        return f"ENTRY    ip={ip} mac={mac} iface={interface}"
    return line


def compact_tcpdump_line(line: str) -> str:
    parsed = parse_tcpdump_tcp(line) if "parse_tcpdump_tcp" in globals() else None
    if parsed:
        source, destination, port, flags = parsed
        source_port = split_endpoint(TCPDUMP_IP_RE.search(line).group("src"))[1]  # type: ignore[union-attr]
        return f"TCP     {source}:{source_port} -> {destination}:{port} flags=[{flags or '-'}]"
    if "ARP" in line.upper():
        return "ARP     " + line.split("ARP", 1)[-1].strip(" ,")
    if "ICMP" in line.upper():
        return "ICMP    " + line.split("ICMP", 1)[-1].strip(" ,")
    return line


def compact_line(source: str, line: str) -> str:
    if source == "NMAP":
        return compact_nmap_line(line)
    if source == "ARP":
        return compact_arp_line(line)
    if source == "TCPDUMP":
        return compact_tcpdump_line(line)
    return line


def new_state() -> dict:
    return {
        "version": 1,
        "arp_initialized": False,
        "arp": {},
        "arp_pending": {},
        "nmap_initialized": False,
        "nmap": {},
        "nmap_pending": {},
        "hostnames": {},
        "identities": {},
    }


class StateStore:
    """Historique JSON atomique pour comparer les observations successives."""

    def __init__(self, filename: str) -> None:
        self.path = None if filename.lower() in ("", "none", "-", "off") else Path(filename).expanduser()
        self.lock = threading.Lock()
        self.data = new_state()
        self.loaded = False
        if self.path and self.path.exists():
            with self.path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                self.data.update(loaded)
                self.loaded = True

    def save(self) -> None:
        if self.path is None:
            return
        with self.lock:
            payload = json.dumps(self.data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(
                f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
            )
            try:
                temporary.write_text(payload, encoding="utf-8")
                os.replace(temporary, self.path)
            finally:
                if temporary.exists():
                    temporary.unlink()


@dataclass
class Context:
    palette: Palette
    suspicious_ports: set[int]
    display: str = "compact"
    resolve_hostnames: bool = False
    state: Optional[StateStore] = None
    event_log: Optional[Path] = None
    allow_hosts: set[str] = field(default_factory=set)
    confirmations: int = DEFAULT_CONFIRMATIONS
    alert_cooldown: float = DEFAULT_ALERT_COOLDOWN
    stop: threading.Event = field(default_factory=threading.Event)
    output_lock: threading.Lock = field(default_factory=threading.Lock)
    process_lock: threading.Lock = field(default_factory=threading.Lock)
    state_lock: threading.RLock = field(default_factory=threading.RLock)
    identity_lock: threading.RLock = field(default_factory=threading.RLock)
    arp_cycle_lock: threading.Lock = field(default_factory=threading.Lock)
    nmap_cycle_lock: threading.Lock = field(default_factory=threading.Lock)
    alert_lock: threading.Lock = field(default_factory=threading.Lock)
    event_lock: threading.Lock = field(default_factory=threading.Lock)
    processes: list[subprocess.Popen[str]] = field(default_factory=list)
    recent_alerts: dict[str, float] = field(default_factory=dict)
    nmap_current_host: Optional[str] = None
    hostname_cache: dict[str, str] = field(default_factory=dict)
    mac_cache: dict[str, str] = field(default_factory=dict)
    announced_identities: set[str] = field(default_factory=set)
    hostname_resolution_done: bool = False

    def section(self, title: str) -> None:
        line = f"\n{'=' * 12} {title} {'=' * 12}"
        with self.output_lock:
            print(self.palette.header(line), flush=True)

    def format_line(self, source: str, line: str) -> str:
        if self.display == "raw":
            return line
        if source == "NMAP":
            report = NMAP_REPORT_RE.search(line) if "NMAP_REPORT_RE" in globals() else None
            if report:
                report_value = report.group(1).strip()
                address = nmap_host_key(report_value)
                discovered_name = nmap_host_name(report_value)
                with self.identity_lock:
                    if discovered_name:
                        self.hostname_cache[address] = discovered_name
                    display_value = self.display_host(address)
                if display_value != report_value:
                    line = f"{line[:report.start(1)]}{display_value}{line[report.end(1):]}"
                self.nmap_current_host = display_value
            formatted = compact_line(source, line)
            if formatted.startswith("OPEN") and self.nmap_current_host:
                return f"{formatted} host={self.nmap_current_host}"
            return formatted
        if source == "ARP":
            match = ARP_LINE_RE.search(line) if "ARP_LINE_RE" in globals() else None
            if match:
                address = match.group("ip").strip()
                if self.hostname_cache.get(address):
                    mac = normalise_mac(match.group("mac"))
                    interface = match.group("interface")
                    label = self.display_host(address)
                    if "incomplete" in mac:
                        return f"INCOMPLETE host={label} iface={interface}"
                    return f"ENTRY    host={label} iface={interface}"
        if source == "TCPDUMP":
            parsed = parse_tcpdump_tcp(line)
            if parsed:
                source_host, destination_host, destination_port, flags = parsed
                endpoint_match = TCPDUMP_IP_RE.search(line)
                if endpoint_match:
                    source_port = split_endpoint(endpoint_match.group("src"))[1]
                    source_label = self.display_host(source_host, include_mac=False)
                    destination_label = self.display_host(destination_host, include_mac=False)
                    return (
                        f"TCP     {source_label}:{source_port} -> "
                        f"{destination_label}:{destination_port} flags=[{flags or '-'}]"
                    )
        return compact_line(source, line)

    def display_host(self, host: str, include_mac: bool = True) -> str:
        with self.identity_lock:
            name = self.hostname_cache.get(host)
            label = f"{name} ({host})" if name else host
            if include_mac and self.mac_cache.get(host):
                label += f" mac={self.mac_cache[host]}"
            return label

    def emit(self, level: str, source: str, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        tags = {
            "dim": "[....]",
            "info": "[INFO]",
            "ok": "[ OK ]",
            "warn": "[WARN]",
            "suspect": "[ALERT]",
        }
        prefix = f"{timestamp} {tags.get(level, '[INFO]')} {source:<8} |"
        if level == "suspect":
            rendered = self.palette.suspect(f"{prefix} {message}")
        elif level == "warn":
            rendered = self.palette.warn(f"{prefix} {message}")
        elif level == "ok":
            rendered = self.palette.ok(f"{prefix} {message}")
        elif level == "dim":
            rendered = self.palette.dim(f"{prefix} {message}")
        else:
            rendered = self.palette.info(f"{prefix} {message}")
        with self.output_lock:
            print(rendered, flush=True)

    def add_process(self, process: subprocess.Popen[str]) -> None:
        with self.process_lock:
            self.processes.append(process)

    def remove_process(self, process: subprocess.Popen[str]) -> None:
        with self.process_lock:
            if process in self.processes:
                self.processes.remove(process)

    def save_state(self) -> None:
        if self.state is None:
            return
        try:
            self.state.save()
        except (OSError, ValueError, TypeError) as exc:
            self.emit("warn", "STATE", f"historique non sauvegardé : {exc}")

    def alert(
        self,
        rule: str,
        source: str,
        message: str,
        fingerprint: Optional[str] = None,
        level: str = "suspect",
    ) -> bool:
        """Affiche et journalise une alerte en respectant un délai anti-répétition."""
        key = f"{rule}:{fingerprint or message}"
        now = time.time()
        with self.alert_lock:
            previous = self.recent_alerts.get(key)
            if previous is not None and now - previous < self.alert_cooldown:
                return False
            self.recent_alerts[key] = now
        self.emit(level, source, f"{rule}: {message}")
        if self.event_log is not None:
            record = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "epoch": now,
                "rule": rule,
                "source": source,
                "message": message,
            }
            try:
                with self.event_lock:
                    self.event_log.parent.mkdir(parents=True, exist_ok=True)
                    with self.event_log.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError as exc:
                self.emit("warn", "STATE", f"événement non journalisé : {exc}")
        return True

    def stop_processes(self) -> None:
        with self.process_lock:
            processes = list(self.processes)
        for process in processes:
            if process.poll() is None:
                try:
                    # start_new_session=True permet de terminer aussi un éventuel
                    # tcpdump lancé derrière sudo, sans toucher au terminal parent.
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass


def command_path(command: str) -> Optional[str]:
    return shutil.which(command)


def default_interface() -> str:
    """Retourne l'interface de la route par défaut, généralement en0 ou en1."""
    route = command_path("route")
    if route:
        try:
            result = subprocess.run(
                [route, "-n", "get", "default"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            match = re.search(r"^interface:\s*(\S+)", result.stdout, re.MULTILINE)
            if match:
                return match.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    netstat = command_path("netstat")
    if netstat:
        output = command_output([netstat, "-rn", "-f", "inet"], timeout=3)
        match = re.search(r"^default\s+\S+\s+\S+\s+(\S+)", output, re.MULTILINE)
        if match:
            return match.group(1)
    try:
        for _, name in socket.if_nameindex():
            if name.startswith(("en", "bridge")):
                return name
    except OSError:
        pass
    return "en0"


def parse_ports(value: str) -> set[int]:
    """Valide un port ou une liste de ports/ranges et retourne l'ensemble obtenu."""
    ports: set[int] = set()
    if not value.strip():
        raise ValueError("la liste de ports ne peut pas être vide")
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise ValueError(f"liste de ports invalide : {value!r}")
        if "-" in item:
            parts = item.split("-")
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise ValueError(f"intervalle de ports invalide : {item!r}")
            start, end = (int(part) for part in parts)
            if start > end:
                raise ValueError(f"intervalle inversé : {item!r}")
            if start < 1 or end > 65535:
                raise ValueError("les ports doivent être compris entre 1 et 65535")
            ports.update(range(start, end + 1))
        elif item.isdigit():
            ports.add(int(item))
        else:
            raise ValueError(f"port invalide : {item!r}")
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("les ports doivent être compris entre 1 et 65535")
    return ports


def nmap_port_expression(value: str) -> str:
    parse_ports(value)
    return value.replace(" ", "")


def validate_target(target: str) -> str:
    """Autorise les IP, CIDR et noms d'hôte sans interprétation par un shell."""
    target = target.strip()
    if not target or len(target) > 253:
        raise ValueError("cible vide ou trop longue")
    if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:/%" for char in target):
        raise ValueError("caractères non autorisés dans la cible")
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            socket.getaddrinfo(target, None)
        except socket.gaierror as exc:
            raise ValueError(f"cible introuvable ou invalide : {target}") from exc
    return target


def validate_interface(interface: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface):
        raise ValueError(f"interface invalide : {interface!r}")
    return interface


def parse_allow_hosts(values: Optional[list[str]]) -> set[str]:
    allowed: set[str] = set()
    for value in values or []:
        for host in value.split(","):
            host = host.strip()
            if host:
                allowed.add(host)
    return allowed


def interface_ipv4(interface: str) -> Optional[str]:
    ipconfig = command_path("ipconfig")
    if ipconfig:
        try:
            result = subprocess.run(
                [ipconfig, "getifaddr", interface],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        address = result.stdout.strip() if result is not None else ""
        try:
            ipaddress.ip_address(address)
            return address
        except ValueError:
            pass

    ifconfig = command_path("ifconfig")
    if not ifconfig:
        return None
    try:
        result = subprocess.run(
            [ifconfig, interface],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})\b", result.stdout)
    if not match:
        return None
    try:
        ipaddress.ip_address(match.group(1))
    except ValueError:
        return None
    return match.group(1)


def classify_nmap(line: str, suspicious_ports: set[int]) -> str:
    match = re.search(r"(?<!\d)(\d{1,5})/(?:tcp|udp)\s+open\b", line, re.IGNORECASE)
    if match and int(match.group(1)) in suspicious_ports:
        return "suspect"
    if match:
        return "ok"
    if "Host is up" in line:
        return "ok"
    return "info"


def classify_arp(line: str, _suspicious_ports: set[int]) -> str:
    lowered = line.lower()
    if "incomplete" in lowered or "(incomplete)" in lowered:
        # Une résolution ARP sans réponse est fréquente pour des IP libres,
        # des entrées expirées ou pendant un scan. Elle mérite un résumé jaune,
        # pas une alerte rouge par ligne.
        return "dim"
    if "arp" in lowered:
        return "ok"
    return "info"


def classify_tcpdump(line: str, suspicious_ports: set[int]) -> str:
    lowered = line.lower()
    if "icmp redirect" in lowered or "authentication failure" in lowered:
        return "suspect"
    # tcpdump affiche souvent le port destination sous la forme « adresse.23: ».
    port_matches = re.findall(r"\.(\d{1,5}):", line)
    if any(int(port) in suspicious_ports for port in port_matches):
        return "suspect"
    if "flags [s]" in lowered:
        return "warn"
    return "info"


ARP_LINE_RE = re.compile(
    r"\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[^\s]+)\s+on\s+(?P<interface>\S+)",
    re.IGNORECASE,
)
NMAP_REPORT_RE = re.compile(r"Nmap scan report for\s+(.+)$", re.IGNORECASE)
NMAP_OPEN_RE = re.compile(r"(?<!\d)(\d{1,5})/(tcp|udp)\s+open\b", re.IGNORECASE)
TCPDUMP_IP_RE = re.compile(
    r"\bIP6?\s+(?P<src>\S+)\s+>\s+(?P<dst>[^:]+):\s+Flags\s+\[(?P<flags>[^\]]*)\]",
    re.IGNORECASE,
)


def normalise_mac(value: str) -> str:
    return value.strip("() ").lower()


def parse_arp_snapshot(lines: list[str]) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for line in lines:
        match = ARP_LINE_RE.search(line)
        if not match:
            continue
        ip = match.group("ip").strip()
        mac = normalise_mac(match.group("mac"))
        if mac in {"incomplete", "(incomplete)"}:
            continue
        entries[ip] = {"mac": mac, "interface": match.group("interface")}
    return entries


def nmap_host_key(value: str) -> str:
    """Retourne une clé stable même lorsque Nmap affiche un nom DNS."""
    match = re.match(r"^.+\s+\(([^)]+)\)$", value.strip())
    return match.group(1).strip() if match else value.strip()


def nmap_host_name(value: str) -> Optional[str]:
    """Extrait le nom d'un rapport Nmap de la forme nom (adresse)."""
    match = re.match(r"^(.+?)\s+\(([^)]+)\)$", value.strip())
    if not match:
        return None
    name, address = match.group(1).strip(), match.group(2).strip()
    return name if name and name != address else None


def parse_nmap_hostnames(lines: list[str]) -> dict[str, str]:
    hostnames: dict[str, str] = {}
    for line in lines:
        report = NMAP_REPORT_RE.search(line)
        if not report:
            continue
        value = report.group(1).strip()
        name = nmap_host_name(value)
        if name:
            hostnames[nmap_host_key(value)] = name
    return hostnames


def parse_nmap_snapshot(lines: list[str]) -> dict[str, list[str]]:
    results: dict[str, set[str]] = {}
    current_host: Optional[str] = None
    for line in lines:
        report = NMAP_REPORT_RE.search(line)
        if report:
            current_host = nmap_host_key(report.group(1))
            results.setdefault(current_host, set())
            continue
        port = NMAP_OPEN_RE.search(line)
        if current_host and port:
            results[current_host].add(f"{port.group(1)}/{port.group(2).lower()}")
    return {host: sorted(ports) for host, ports in results.items()}


def split_endpoint(endpoint: str) -> Optional[tuple[str, int]]:
    endpoint = endpoint.strip().rstrip(",")
    match = re.match(r"^(?P<host>.+)\.(?P<port>\d+)$", endpoint)
    if not match:
        return None
    return match.group("host"), int(match.group("port"))


def parse_tcpdump_tcp(line: str) -> Optional[tuple[str, str, int, str]]:
    match = TCPDUMP_IP_RE.search(line)
    if not match:
        return None
    source = split_endpoint(match.group("src"))
    destination = split_endpoint(match.group("dst"))
    if source is None or destination is None:
        return None
    return source[0], destination[0], destination[1], match.group("flags").upper()


def detect_arp_changes(
    context: Context,
    current: dict[str, dict[str, str]],
    confirmations: int,
) -> None:
    if context.state is None:
        return
    data = context.state.data
    known = data.setdefault("arp", {})
    pending = data.setdefault("arp_pending", {})
    if not data.get("arp_initialized", False):
        data["arp"] = {
            ip: {**entry, "history": [entry["mac"]]}
            for ip, entry in current.items()
        }
        data["arp_initialized"] = True
        context.emit("dim", "RULE", f"baseline ARP initialisée ({len(current)} entrée(s))")
        context.save_state()
        return

    for ip, entry in current.items():
        mac = entry["mac"]
        old = known.get(ip)
        if old is None:
            known[ip] = {**entry, "history": [mac]}
            if ip not in context.allow_hosts:
                context.alert(
                    "NEW_DEVICE",
                    "ARP",
                    f"nouvel hôte détecté : {ip} ({mac})",
                    fingerprint=ip,
                )
            continue

        old_mac = normalise_mac(str(old.get("mac", "")))
        if mac == old_mac:
            pending.pop(ip, None)
            old["interface"] = entry["interface"]
            continue

        candidate = pending.get(ip, {})
        count = int(candidate.get("count", 0)) + 1 if candidate.get("mac") == mac else 1
        pending[ip] = {"mac": mac, "count": count}
        if count < confirmations:
            context.emit(
                "warn",
                "ARP",
                f"changement IP/MAC en attente de confirmation : {ip} {old_mac} -> {mac} ({count}/{confirmations})",
            )
            continue

        history = [normalise_mac(str(item)) for item in old.get("history", [old_mac])]
        rule = "ARP_FLIP_FLOP" if mac in history else "ARP_MAC_CHANGED"
        if ip not in context.allow_hosts:
            context.alert(
                rule,
                "ARP",
                f"{ip} associe maintenant {mac} au lieu de {old_mac}",
                fingerprint=ip,
            )
        history.append(mac)
        old.update({"mac": mac, "interface": entry["interface"], "history": history[-8:]})
        pending.pop(ip, None)

    context.save_state()


def detect_nmap_changes(
    context: Context,
    current: dict[str, list[str]],
    confirmations: int,
) -> None:
    if context.state is None:
        return
    data = context.state.data
    known = data.setdefault("nmap", {})
    pending = data.setdefault("nmap_pending", {})
    if not data.get("nmap_initialized", False):
        data["nmap"] = {host: {"ports": ports} for host, ports in current.items()}
        data["nmap_initialized"] = True
        context.emit("dim", "RULE", f"baseline Nmap initialisée ({len(current)} hôte(s))")
        context.save_state()
        return

    for host, ports in current.items():
        if host not in known:
            known[host] = {"ports": ports}
            if host not in context.allow_hosts:
                context.alert(
                    "NEW_NMAP_HOST",
                    "NMAP",
                    f"nouvel hôte répondant : {context.display_host(host)}",
                    fingerprint=host,
                )
            continue

        stable = set(known[host].get("ports", []))
        observed = set(ports)
        for port in sorted(observed - stable):
            key = f"{host}:{port}:add"
            candidate = pending.get(key, {})
            count = int(candidate.get("count", 0)) + 1 if candidate.get("kind") == "add" else 1
            pending[key] = {"kind": "add", "count": count}
            if count >= confirmations:
                if host not in context.allow_hosts:
                    context.alert(
                        "NEW_OPEN_PORT",
                        "NMAP",
                        f"nouveau port ouvert : {context.display_host(host)} {port}",
                        fingerprint=f"{host}:{port}",
                    )
                stable.add(port)
                pending.pop(key, None)

        for port in sorted(stable - observed):
            key = f"{host}:{port}:remove"
            candidate = pending.get(key, {})
            count = int(candidate.get("count", 0)) + 1 if candidate.get("kind") == "remove" else 1
            pending[key] = {"kind": "remove", "count": count}
            if count >= confirmations:
                stable.discard(port)
                pending.pop(key, None)

        for port in observed & stable:
            pending.pop(f"{host}:{port}:add", None)
            pending.pop(f"{host}:{port}:remove", None)
        known[host]["ports"] = sorted(stable)

    context.save_state()


class ScanDetector:
    """Détecte les scans par fenêtre glissante, sans conserver les paquets."""

    def __init__(
        self,
        context: Context,
        window: float,
        port_threshold: int,
        host_threshold: int,
        stealth_threshold: int,
    ) -> None:
        self.context = context
        self.window = window
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.stealth_threshold = stealth_threshold
        self.events: dict[str, deque[tuple[float, str, int, str]]] = defaultdict(deque)

    def observe(self, line: str) -> None:
        lowered = line.lower()
        if "icmp redirect" in lowered:
            self.context.alert(
                "ICMP_REDIRECT",
                "RULE",
                "redirection ICMP observée",
                fingerprint="icmp-redirect",
            )
        parsed = parse_tcpdump_tcp(line)
        if parsed is None:
            return
        source, destination, port, flags = parsed
        if source in self.context.allow_hosts or source in {"127.0.0.1", "::1"}:
            return
        has_ack = "A" in flags or "." in flags
        is_syn = "S" in flags and not has_ack
        is_stealth = ("F" in flags and "S" not in flags and not has_ack) or flags.strip() == ""
        if not is_syn and not is_stealth:
            return
        now = time.time()
        queue = self.events[source]
        queue.append((now, destination, port, "stealth" if is_stealth else "syn"))
        while queue and now - queue[0][0] > self.window:
            queue.popleft()
        ports = {item[2] for item in queue}
        hosts = {item[1] for item in queue}
        stealth_ports = {item[2] for item in queue if item[3] == "stealth"}
        if len(ports) >= self.port_threshold or len(hosts) >= self.host_threshold:
            self.context.alert(
                "PORT_SCAN",
                "RULE",
                f"{source} a touché {len(ports)} ports sur {len(hosts)} hôte(s) en {self.window:g}s",
                fingerprint=source,
            )
        if len(stealth_ports) >= self.stealth_threshold:
            self.context.alert(
                "STEALTH_SCAN",
                "RULE",
                f"{source} présente {len(stealth_ports)} ports avec des drapeaux FIN/NULL",
                fingerprint=f"stealth:{source}",
            )


Classifier = Callable[[str, set[int]], str]


def run_stream(
    context: Context,
    command: list[str],
    source: str,
    classifier: Classifier,
    dry_run: bool = False,
    line_observer: Optional[Callable[[str], None]] = None,
) -> int:
    """Lance une commande et retransmet sa sortie ligne par ligne."""
    context.emit("dim", source, "$ " + shlex.join(command))
    if dry_run:
        return 0
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=None,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
    except OSError as exc:
        context.emit("suspect", source, f"impossible de lancer la commande : {exc}")
        return 127

    context.add_process(process)
    try:
        assert process.stdout is not None
        for raw_line in process.stdout:
            if context.stop.is_set():
                break
            # Évite qu'une sortie externe puisse injecter des séquences ANSI
            # ou des caractères de contrôle dans l'affichage coloré.
            line = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw_line.rstrip())
            if line:
                if line_observer is not None:
                    line_observer(line)
                level = classifier(line, context.suspicious_ports)
                if (
                    source == "ARP"
                    and context.display == "compact"
                    and level == "dim"
                    and "incomplete" in line.lower()
                ):
                    continue
                rendered_line = context.format_line(source, line)
                context.emit(level, source, rendered_line)
        if context.stop.is_set() and process.poll() is None:
            process.terminate()
        return_code = process.wait()
    finally:
        context.remove_process(process)

    if return_code not in (0, 130) and not context.stop.is_set():
        context.emit("warn", source, f"commande terminée avec le code {return_code}")
    return return_code


def nmap_command(
    target: str,
    ports: str,
    timing: int,
    resolve_hostnames: bool = False,
) -> list[str]:
    name_resolution = "-R" if resolve_hostnames else "-n"
    return [
        command_path("nmap") or "nmap",
        name_resolution,
        f"-T{timing}",
        "--open",
        "--reason",
        "--stats-every",
        "5s",
        "-sT",
        "-p",
        nmap_port_expression(ports),
        target,
    ]


def arp_command() -> list[str]:
    return [command_path("arp") or "arp", "-an"]


def persist_identity_cache(context: Context) -> None:
    if context.state is None:
        return
    with context.state_lock:
        with context.identity_lock:
            context.state.data["hostnames"] = dict(sorted(context.hostname_cache.items()))
            context.state.data["identities"] = {
                address: {
                    "hostname": context.hostname_cache.get(address, ""),
                    "mac": context.mac_cache.get(address, ""),
                }
                for address in sorted(set(context.hostname_cache) | set(context.mac_cache))
            }
        context.state.save()


def nmap_resolution_for_run(context: Context) -> bool:
    """Résout les noms au premier scan seulement, puis utilise le cache."""
    if not context.resolve_hostnames or context.hostname_resolution_done:
        return False
    context.hostname_resolution_done = True
    return not bool(context.hostname_cache)


def announce_complete_identities(context: Context) -> None:
    with context.identity_lock:
        pending = [
            address
            for address in sorted(set(context.hostname_cache) & set(context.mac_cache))
            if address not in context.announced_identities
        ]
        for address in pending:
            context.announced_identities.add(address)
    for address in pending:
        context.emit("info", "IDENTITY", f"host={context.display_host(address)}")


def remember_nmap_hostnames(context: Context, lines: list[str]) -> None:
    if not context.resolve_hostnames:
        return
    discovered = parse_nmap_hostnames(lines)
    with context.identity_lock:
        changed = {
            address: name
            for address, name in discovered.items()
            if context.hostname_cache.get(address) != name
        }
        if changed:
            context.hostname_cache.update(changed)
    if not changed:
        return
    persist_identity_cache(context)
    context.emit("dim", "NMAP", f"{len(changed)} nom(s) mémorisé(s) pour les prochains scans")
    announce_complete_identities(context)


def remember_arp_identities(context: Context, lines: list[str]) -> None:
    entries = parse_arp_snapshot(lines)
    with context.identity_lock:
        changed = {
            address: entry["mac"]
            for address, entry in entries.items()
            if context.mac_cache.get(address) != entry["mac"]
        }
        if changed:
            context.mac_cache.update(changed)
    if not changed:
        return
    persist_identity_cache(context)
    context.emit("dim", "ARP", f"{len(changed)} adresse(s) MAC mémorisée(s) pour les prochains affichages")
    announce_complete_identities(context)


def tcpdump_command(
    interface: str,
    expression: str,
    count: Optional[int],
    use_sudo: bool,
    buffer_kib: int,
) -> list[str]:
    if buffer_kib < 1:
        raise ValueError("--buffer-kib doit être supérieur ou égal à 1")
    tcpdump = command_path("tcpdump") or "tcpdump"
    command = [
        tcpdump,
        "-l",               # sortie ligne par ligne dans le pipe Python
        "--immediate-mode", # livraison immédiate des paquets à tcpdump
        "-n",
        "-tttt",
        "-e",
        "-s",
        "96",               # en-têtes uniquement : moins de CPU et de mémoire
        "-B",
        str(buffer_kib),
        "-i",
        interface,
    ]
    if count is not None:
        command.extend(["-c", str(count)])
    if expression.strip():
        command.extend(shlex.split(expression))
    if use_sudo:
        command.insert(0, "sudo")
    return command


def wait_or_stop(context: Context, seconds: float) -> None:
    context.stop.wait(max(0.1, seconds))


def run_capture(
    context: Context,
    args: argparse.Namespace,
    detector: Optional[ScanDetector] = None,
) -> int:
    interface = validate_interface(args.interface)
    if args.count is not None and args.count < 1:
        raise ValueError("--count doit être supérieur ou égal à 1")
    command = tcpdump_command(
        interface,
        args.filter,
        args.count,
        args.sudo_tcpdump,
        args.buffer_kib,
    )
    context.section("RADARSCOPE / TCPDUMP")
    context.emit("info", "CONFIG", f"interface={interface} | filtre={args.filter or 'tous les paquets'}")
    return run_stream(
        context,
        command,
        "TCPDUMP",
        classify_tcpdump,
        args.dry_run,
        detector.observe if detector is not None else None,
    )


def run_scan(context: Context, args: argparse.Namespace) -> int:
    target = validate_target(args.target)
    parse_ports(args.ports)
    command = nmap_command(target, args.ports, args.timing, args.resolve_hostnames)
    context.section("RADARSCOPE / NMAP")
    context.emit(
        "info",
        "NMAP",
        f"scan de {target} ; ports examinés : {args.ports} ; timing T{args.timing}",
    )
    context.emit(
        "info",
        "NMAP",
        f"résolution DNS inverse : {'oui' if args.resolve_hostnames else 'non'}",
    )
    return run_stream(context, command, "NMAP", classify_nmap, args.dry_run)


def run_arp(context: Context, args: argparse.Namespace) -> int:
    context.section("RADARSCOPE / ARP")
    lines: list[str] = []
    return_code = run_stream(context, arp_command(), "ARP", classify_arp, args.dry_run, lines.append)
    if not args.dry_run:
        report_incomplete_arp(context, lines)
    return return_code


def report_incomplete_arp(context: Context, lines: list[str]) -> None:
    count = sum(1 for line in lines if "incomplete" in line.lower())
    if count:
        context.alert(
            "ARP_INCOMPLETE",
            "RULE",
            f"{count} entrée(s) sans réponse ; état souvent transitoire, non classé comme attaque",
            fingerprint="arp-incomplete",
            level="warn",
        )


def periodic_arp(context: Context, interval: float, dry_run: bool) -> None:
    first = True
    while not context.stop.is_set():
        if not first:
            context.emit("dim", "ARP", f"nouveau relevé (toutes les {interval:g} s)")
        lines: list[str] = []
        with context.arp_cycle_lock:
            run_stream(context, arp_command(), "ARP", classify_arp, dry_run, lines.append)
            if not dry_run:
                report_incomplete_arp(context, lines)
                with context.state_lock:
                    remember_arp_identities(context, lines)
                    detect_arp_changes(context, parse_arp_snapshot(lines), context.confirmations)
        first = False
        if dry_run:
            return
        wait_or_stop(context, interval)


def periodic_nmap(context: Context, args: argparse.Namespace) -> None:
    target = validate_target(args.target)
    parse_ports(args.ports)
    first = True
    while not context.stop.is_set():
        if not first:
            context.emit("dim", "NMAP", f"nouveau scan (toutes les {args.scan_interval:g} s)")
        lines: list[str] = []
        resolve_now = nmap_resolution_for_run(context)
        with context.nmap_cycle_lock:
            run_stream(
                context,
                nmap_command(target, args.ports, args.timing, resolve_now),
                "NMAP",
                classify_nmap,
                args.dry_run,
                lines.append,
            )
            if not args.dry_run:
                with context.state_lock:
                    remember_nmap_hostnames(context, lines)
                    detect_nmap_changes(context, parse_nmap_snapshot(lines), context.confirmations)
        first = False
        if args.dry_run:
            return
        wait_or_stop(context, args.scan_interval)


def stop_after(context: Context, duration: float) -> None:
    if duration > 0 and not context.stop.wait(duration):
        context.emit("info", "WATCH", f"durée de {duration:g} s atteinte ; arrêt propre")
        context.stop.set()
        context.stop_processes()


def run_watch(context: Context, args: argparse.Namespace) -> int:
    interface = validate_interface(args.interface)
    target = validate_target(args.target)
    parse_ports(args.ports)
    if args.arp_interval <= 0 or args.scan_interval <= 0:
        raise ValueError("les intervalles doivent être supérieurs à 0")
    if args.duration < 0:
        raise ValueError("--duration ne peut pas être négatif")
    if args.count is not None and args.count < 1:
        raise ValueError("--count doit être supérieur ou égal à 1")
    if args.buffer_kib < 1:
        raise ValueError("--buffer-kib doit être supérieur ou égal à 1")
    if args.confirmations < 1:
        raise ValueError("--confirmations doit être supérieur ou égal à 1")
    if args.alert_cooldown < 0:
        raise ValueError("--alert-cooldown ne peut pas être négatif")
    if args.scan_window <= 0:
        raise ValueError("--scan-window doit être supérieur à 0")
    if args.scan_ports_threshold < 1 or args.scan_hosts_threshold < 1 or args.stealth_threshold < 1:
        raise ValueError("les seuils de détection doivent être supérieurs à 0")

    context.confirmations = args.confirmations
    context.allow_hosts.update(parse_allow_hosts(args.allow_host))
    local_ip = interface_ipv4(interface)
    context.section("RADARSCOPE / SURVEILLANCE")
    if local_ip:
        context.allow_hosts.add(local_ip)
        context.emit("dim", "RULE", f"adresse locale ignorée pour les scans : {local_ip}")
    context.emit("info", "CONFIG", f"interface={interface} | cible nmap={target}")
    context.emit(
        "info",
        "CONFIG",
        f"display={context.display} | arp={args.arp_interval:g}s | nmap={args.scan_interval:g}s | "
        f"hostnames={'dns' if args.resolve_hostnames else 'off'}",
    )
    context.emit(
        "info",
        "STATE",
        f"historique={args.state_file} | alertes={args.event_log}",
    )
    context.emit(
        "info",
        "RULE",
        f"scan={args.scan_ports_threshold} ports/{args.scan_hosts_threshold} hôtes en {args.scan_window:g}s | confirmations={args.confirmations}",
    )
    context.emit(
        "warn",
        "WATCH",
        "utilise uniquement ce programme sur un réseau et des machines que tu administres",
    )
    if args.dry_run:
        context.emit("dim", "WATCH", "mode simulation : aucune commande ne sera exécutée")
        run_stream(context, arp_command(), "ARP", classify_arp, True)
        resolve_now = nmap_resolution_for_run(context)
        run_stream(
            context,
            nmap_command(target, args.ports, args.timing, resolve_now),
            "NMAP",
            classify_nmap,
            True,
        )
        run_stream(
            context,
            tcpdump_command(
                interface,
                args.filter,
                args.count,
                args.sudo_tcpdump,
                args.buffer_kib,
            ),
            "TCPDUMP",
            classify_tcpdump,
            True,
        )
        return 0

    detector = ScanDetector(
        context,
        args.scan_window,
        args.scan_ports_threshold,
        args.scan_hosts_threshold,
        args.stealth_threshold,
    )

    threads = [
        threading.Thread(target=periodic_arp, args=(context, args.arp_interval, False), name="arp"),
        threading.Thread(target=periodic_nmap, args=(context, args), name="nmap"),
        threading.Thread(
            target=run_capture,
            args=(
                context,
                argparse.Namespace(
                    interface=interface,
                    filter=args.filter,
                    count=args.count,
                    sudo_tcpdump=args.sudo_tcpdump,
                    buffer_kib=args.buffer_kib,
                    dry_run=False,
                ),
                detector,
            ),
            name="tcpdump",
        ),
    ]
    if args.duration:
        threads.append(threading.Thread(target=stop_after, args=(context, args.duration), name="timer"))

    for thread in threads:
        thread.start()
    try:
        while any(thread.is_alive() for thread in threads):
            for thread in threads:
                thread.join(timeout=0.4)
    except KeyboardInterrupt:
        context.emit("info", "WATCH", "interruption demandée ; arrêt des commandes...")
        context.stop.set()
        context.stop_processes()
    finally:
        context.stop.set()
        context.stop_processes()
        for thread in threads:
            thread.join(timeout=2)
    return 0


def check_command(context: Context, name: str) -> bool:
    path = command_path(name)
    if path:
        context.emit("ok", "CHECK", f"{name:<8} trouvé : {path}")
        return True
    context.emit("suspect", "CHECK", f"{name:<8} absent du PATH")
    return False


def run_reset_hostnames(context: Context, args: argparse.Namespace) -> int:
    """Vide uniquement le cache des noms et des associations MAC."""
    if args.dry_run:
        context.emit("dim", "STATE", f"simulation : cache hostname/MAC à réinitialiser dans {args.state_file}")
        return 0
    try:
        state = StateStore(args.state_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"impossible de lire {args.state_file} : {exc}") from exc
    had_cache = bool(state.data.get("hostnames") or state.data.get("identities"))
    state.data["hostnames"] = {}
    state.data["identities"] = {}
    state.save()
    if had_cache:
        context.emit("ok", "STATE", f"cache hostname/MAC réinitialisé : {args.state_file}")
    else:
        context.emit("info", "STATE", f"aucun cache hostname/MAC à réinitialiser : {args.state_file}")
    return 0


def run_doctor(context: Context, _args: argparse.Namespace) -> int:
    context.section("RADARSCOPE / DIAGNOSTIC")
    context.emit("info", "CHECK", f"macOS : {platform_name()}")
    statuses = [check_command(context, command) for command in ("nmap", "arp", "tcpdump")]
    check_command(context, "lsof")
    all_present = all(statuses)
    context.emit("info", "CHECK", f"interface par défaut : {default_interface()}")
    if not all_present:
        context.emit("warn", "CHECK", "installe nmap avec Homebrew : brew install nmap")
        return 1
    context.emit("ok", "CHECK", "prêt à lancer une surveillance")
    return 0


def platform_name() -> str:
    return f"{sys.platform} ({os.uname().release})" if hasattr(os, "uname") else sys.platform


def command_output(command: list[str], timeout: float = 3.0) -> str:
    """Retourne la sortie d'une commande locale sans interrompre le dashboard."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def public_ip_address() -> Optional[str]:
    """Retourne l'IP publique observée par un service externe, avec cache court."""
    global _public_ip_cache
    now = time.monotonic()
    with _public_ip_cache_lock:
        checked_at, cached = _public_ip_cache
        ttl = PUBLIC_IP_CACHE_TTL if cached else PUBLIC_IP_FAILURE_TTL
        if now - checked_at < ttl:
            return cached
        curl = command_path("curl")
        if not curl:
            _public_ip_cache = (now, None)
            return None
        output = command_output(
            [curl, "-4", "-fsS", "--connect-timeout", "3", "--max-time", "5", PUBLIC_IP_ENDPOINT],
            timeout=6,
        )
        candidate = output.splitlines()[0].strip() if output else ""
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            address = None
        if address is None or address.is_loopback or address.is_unspecified or address.is_multicast or address.is_reserved:
            candidate = None
        _public_ip_cache = (now, candidate)
        return candidate


def sysctl_value(name: str) -> Optional[str]:
    sysctl = command_path("sysctl")
    if not sysctl:
        return None
    value = command_output([sysctl, "-n", name], timeout=2).strip()
    return value or None


def parse_vm_stat(output: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        match = re.match(r"^Pages\s+(.+?):\s+(\d+)", line)
        if not match:
            continue
        key = re.sub(r"[^a-z0-9]+", "_", match.group(1).lower()).strip("_")
        values[key] = int(match.group(2))
    return values


def parse_human_bytes(value: str) -> Optional[int]:
    match = re.search(r"(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)", value, re.IGNORECASE)
    if not match:
        return None
    number = float(match.group(1))
    multiplier = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    return int(number * multiplier[match.group(2).upper()])


def collect_memory_snapshot() -> dict[str, object]:
    total_text = sysctl_value("hw.memsize")
    vm_stat_output = command_output([command_path("vm_stat") or "vm_stat"], timeout=2)
    page_size_match = re.search(r"page size of (\d+) bytes", vm_stat_output, re.IGNORECASE)
    page_size_text = sysctl_value("hw.pagesize") or (page_size_match.group(1) if page_size_match else "4096")
    try:
        total_bytes = int(total_text or "0")
        page_size = int(page_size_text)
    except ValueError:
        total_bytes = 0
        page_size = 4096
    if total_bytes <= 0:
        hardware = command_output(
            [command_path("system_profiler") or "system_profiler", "SPHardwareDataType", "-json"],
            timeout=5,
        )
        try:
            overview = json.loads(hardware).get("SPHardwareDataType", [{}])[0]
            total_bytes = parse_human_bytes(str(overview.get("physical_memory", ""))) or 0
        except (ValueError, TypeError, IndexError, AttributeError):
            total_bytes = 0
    if total_bytes <= 0 or page_size <= 0:
        return {"total_bytes": None, "used_bytes": None, "used_percent": None}

    pages = parse_vm_stat(vm_stat_output)
    available_pages = sum(pages.get(name, 0) for name in ("free", "inactive", "speculative"))
    available_bytes = min(total_bytes, available_pages * page_size)
    used_bytes = max(0, total_bytes - available_bytes)
    return {
        "total_bytes": total_bytes,
        "used_bytes": used_bytes,
        "available_bytes": available_bytes,
        "used_percent": round((used_bytes / total_bytes) * 100, 1),
    }


def collect_battery_snapshot() -> dict[str, object]:
    pmset = command_path("pmset")
    if not pmset:
        return {"available": False}
    output = command_output([pmset, "-g", "batt"], timeout=2)
    percent_match = re.search(r"(\d+)%", output)
    source_match = re.search(r"Now drawing from '([^']+)'", output)
    if not percent_match and not source_match:
        return {"available": False}
    lowered = output.lower()
    if "charging" in lowered:
        status = "charging"
    elif "charged" in lowered:
        status = "charged"
    elif "discharging" in lowered:
        status = "discharging"
    else:
        status = "unknown"
    return {
        "available": bool(percent_match),
        "percent": int(percent_match.group(1)) if percent_match else None,
        "status": status,
        "source": source_match.group(1) if source_match else None,
    }


def collect_uptime_seconds() -> Optional[int]:
    boot_time = sysctl_value("kern.boottime")
    if not boot_time:
        return None
    match = re.search(r"sec\s*=\s*(\d+)", boot_time)
    if not match:
        return None
    return max(0, int(time.time()) - int(match.group(1)))


def hardware_port_map() -> dict[str, str]:
    """Associe les noms macOS (en0, en1...) à Wi-Fi, Ethernet, Thunderbolt, etc."""
    networksetup = command_path("networksetup")
    if not networksetup:
        return {}
    output = command_output([networksetup, "-listallhardwareports"], timeout=4)
    mapping: dict[str, str] = {}
    current_port: Optional[str] = None
    for line in output.splitlines():
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and current_port:
            device = line.split(":", 1)[1].strip()
            mapping[device] = current_port
            current_port = None
    return mapping


def interface_kind(name: str, hardware_port: Optional[str]) -> str:
    label = (hardware_port or "").lower()
    if "wi-fi" in label or "wifi" in label or name.startswith(("awdl", "llw")):
        return "wifi"
    if "ethernet" in label or "lan" in label or name.startswith("en"):
        return "ethernet"
    if name.startswith("bridge"):
        return "bridge"
    if name.startswith("utun"):
        return "vpn"
    if name == "lo0":
        return "loopback"
    return "other"


def collect_interface_snapshot() -> list[dict[str, object]]:
    names: set[str] = set()
    try:
        names.update(name for _, name in socket.if_nameindex())
    except OSError:
        pass
    ifconfig = command_path("ifconfig")
    if ifconfig:
        output = command_output([ifconfig, "-a"], timeout=4)
        names.update(re.findall(r"^([A-Za-z0-9_.:-]+):\s+flags=", output, re.MULTILINE))
    port_map = hardware_port_map()
    interfaces: list[dict[str, object]] = []
    for name in sorted(names):
        details = command_output([command_path("ifconfig") or "ifconfig", name], timeout=2)
        flags_match = re.search(r"flags=\d+<([^>]+)>", details)
        hardware_port = port_map.get(name)
        lowered = details.lower()
        if "status: inactive" in lowered:
            active = False
        else:
            active = "status: active" in lowered or "RUNNING" in (flags_match.group(1) if flags_match else "")
        ipv4 = interface_ipv4(name)
        kind = interface_kind(name, hardware_port)
        interfaces.append(
            {
                "name": name,
                "ipv4": ipv4,
                "active": active,
                "loopback": name == "lo0",
                "kind": kind,
                "hardware_port": hardware_port or name,
                "selectable": bool(
                    name != "lo0"
                    and not name.startswith(("awdl", "llw"))
                    and kind in {"wifi", "ethernet", "bridge"}
                ),
            }
        )
    return interfaces


def collect_system_snapshot() -> dict[str, object]:
    try:
        loads = [round(value, 2) for value in os.getloadavg()]
    except OSError:
        loads = []
    disk_usage = shutil.disk_usage("/")
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu": {
            "cores": os.cpu_count() or 1,
            "load": loads,
        },
        "memory": collect_memory_snapshot(),
        "disk": {
            "path": "/",
            "total_bytes": disk_usage.total,
            "used_bytes": disk_usage.used,
            "free_bytes": disk_usage.free,
            "used_percent": round((disk_usage.used / disk_usage.total) * 100, 1),
        },
        "battery": collect_battery_snapshot(),
        "uptime_seconds": collect_uptime_seconds(),
        "default_interface": default_interface(),
        "interfaces": collect_interface_snapshot(),
    }


def collect_network_counters() -> dict[str, object]:
    """Lit les compteurs cumulés des interfaces sans capturer le contenu réseau."""
    netstat = command_path("netstat")
    header: list[str] = []
    counters: dict[str, dict[str, int]] = {}
    if netstat:
        output = command_output([netstat, "-ib", "-n"], timeout=3)
        for line in output.splitlines():
            parts = line.split()
            if not header and "Ibytes" in parts and "Obytes" in parts:
                header = parts
                continue
            if not header or len(parts) < len(header) or parts[0] in {"Name", ""}:
                continue
            row = dict(zip(header, parts))
            name = row.get("Name")
            if not name or name in counters:
                continue
            try:
                received = int(row.get("Ibytes", "0"))
                sent = int(row.get("Obytes", "0"))
            except ValueError:
                continue
            counters[name] = {"rx_bytes": received, "tx_bytes": sent}
    if counters:
        return {
            "available": True,
            "rx_bytes": sum(item["rx_bytes"] for item in counters.values()),
            "tx_bytes": sum(item["tx_bytes"] for item in counters.values()),
            "interfaces": counters,
            "source": "netstat",
        }

    nettop = command_path("nettop")
    if nettop:
        output = command_output(
            [nettop, "-n", "-L", "1", "-x", "-J", "interface,bytes_in,bytes_out"],
            timeout=8,
        )
        counters = parse_nettop_counters(output)
        if counters:
            return {
                "available": True,
                "rx_bytes": sum(item["rx_bytes"] for item in counters.values()),
                "tx_bytes": sum(item["tx_bytes"] for item in counters.values()),
                "interfaces": counters,
                "source": "nettop",
            }
    return {"available": False, "rx_bytes": None, "tx_bytes": None, "interfaces": {}, "source": "netstat/nettop"}


def parse_nettop_counters(output: str) -> dict[str, dict[str, int]]:
    """Agrège les octets CSV de nettop par interface réseau."""
    reader = csv.reader(io.StringIO(output))
    header: Optional[list[str]] = None
    counters: dict[str, dict[str, int]] = defaultdict(lambda: {"rx_bytes": 0, "tx_bytes": 0})
    for row in reader:
        if header is None and "interface" in row and "bytes_in" in row and "bytes_out" in row:
            header = row
            continue
        if header is None:
            continue
        try:
            interface_index = header.index("interface")
            rx_index = header.index("bytes_in")
            tx_index = header.index("bytes_out")
            interface = row[interface_index].strip()
            if not interface:
                continue
            received = int(row[rx_index])
            sent = int(row[tx_index])
        except (ValueError, IndexError):
            continue
        counters[interface]["rx_bytes"] += received
        counters[interface]["tx_bytes"] += sent
    return dict(counters)


def select_network_counters(network: dict[str, object], interface: Optional[str]) -> dict[str, object]:
    selected = (interface or "all").strip() or "all"
    interfaces = network.get("interfaces", {})
    if selected != "all":
        values = interfaces.get(selected) if isinstance(interfaces, dict) else None
        if isinstance(values, dict):
            return {
                **network,
                "selected_interface": selected,
                "rx_bytes": values.get("rx_bytes"),
                "tx_bytes": values.get("tx_bytes"),
            }
        return {
            **network,
            "available": False,
            "selected_interface": selected,
            "rx_bytes": None,
            "tx_bytes": None,
        }
    return {**network, "selected_interface": "all"}


def default_gateway() -> Optional[str]:
    route = command_path("route")
    if not route:
        return None
    output = command_output([route, "-n", "get", "default"], timeout=2)
    match = re.search(r"^gateway:\s*(\S+)", output, re.MULTILINE)
    if match:
        return match.group(1)
    netstat = command_path("netstat")
    if netstat:
        output = command_output([netstat, "-rn", "-f", "inet"], timeout=3)
        match = re.search(r"^default\s+(\S+)\s+\S+\s+\S+", output, re.MULTILINE)
        if match:
            return match.group(1)
    return None


def collect_arp_entries() -> list[dict[str, object]]:
    output = command_output([command_path("arp") or "arp", "-an"], timeout=3)
    entries: dict[str, dict[str, object]] = {}
    for line in output.splitlines():
        match = ARP_LINE_RE.search(line)
        if not match:
            continue
        ip = match.group("ip").strip()
        raw_mac = normalise_mac(match.group("mac"))
        incomplete = "incomplete" in raw_mac
        host_prefix = line.split(" (", 1)[0].strip()
        entries[ip] = {
            "ip": ip,
            "hostname": None if host_prefix in {"", "?"} else host_prefix,
            "mac": None if incomplete else raw_mac,
            "interface": match.group("interface"),
            "reachable": not incomplete,
        }
    return sorted(entries.values(), key=lambda item: str(item["ip"]))


def parse_lsof_connections(output: str) -> list[dict[str, object]]:
    connections: list[dict[str, object]] = []
    for line in output.splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9 or not parts[1].isdigit():
            continue
        endpoint = parts[8]
        state_match = re.search(r"\(([^)]+)\)\s*$", endpoint)
        state = state_match.group(1) if state_match else ""
        endpoint_without_state = re.sub(r"\s+\([^)]*\)\s*$", "", endpoint)
        local, separator, remote = endpoint_without_state.partition("->")
        connections.append(
            {
                "command": parts[0],
                "pid": int(parts[1]),
                "user": parts[2],
                "fd": parts[3],
                "protocol": parts[4],
                "endpoint": endpoint,
                "local": local,
                "remote": remote if separator else None,
                "state": state,
            }
        )
    return connections


def collect_connections() -> list[dict[str, object]]:
    lsof = command_path("lsof")
    if not lsof:
        return []
    output = command_output([lsof, "-nP", "-iTCP", "-iUDP"], timeout=5)
    connections = parse_lsof_connections(output)
    return connections[:DEFAULT_SNAPSHOT_LIMIT]


def system_profiler_json(data_type: str) -> object:
    system_profiler = command_path("system_profiler")
    if not system_profiler:
        return {}
    output = command_output([system_profiler, data_type, "-json"], timeout=8)
    if not output:
        return {}
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {}


def ioreg_value(raw: str) -> object:
    value = raw.strip()
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    if value.startswith("<") and value.endswith(">"):
        compact = re.sub(r"[^0-9a-fA-F]", "", value[1:-1])
        if compact and len(compact) % 2 == 0:
            return ":".join(compact[index : index + 2].lower() for index in range(0, len(compact), 2))
    if value in {"Yes", "No"}:
        return value == "Yes"
    try:
        return int(value)
    except ValueError:
        return value


def parse_ioreg_roots(output: str, root_class: str) -> list[dict[str, object]]:
    """Extrait les propriétés directes des périphériques I/O Registry demandés."""
    roots: list[dict[str, object]] = []
    current: Optional[dict[str, object]] = None
    current_indent = -1
    collecting_properties = False
    property_pattern = re.compile(r'^(\s*)\|\s+"([^"]+)"\s*=\s*(.+?)\s*$')
    for line in output.splitlines():
        root_match = re.match(r"^(\s*)\+-o\s+(.+?)\s+<class\s+([^,>]+)", line)
        if root_match:
            indent = len(root_match.group(1))
            if current is not None and (indent <= current_indent or root_match.group(3).strip() == root_class):
                roots.append(current)
                current = None
                current_indent = -1
                collecting_properties = False
            elif current is not None and indent > current_indent:
                collecting_properties = False
            if root_match.group(3).strip() == root_class:
                current = {"name": root_match.group(2).strip(), "properties": {}}
                current_indent = indent
                collecting_properties = True
            continue
        if current is None or not collecting_properties:
            continue
        property_match = property_pattern.match(line)
        if property_match:
            properties = current["properties"]
            if isinstance(properties, dict):
                properties[property_match.group(2)] = ioreg_value(property_match.group(3))
    if current is not None:
        roots.append(current)
    return roots


def collect_ioreg_peripherals(kind: str) -> list[dict[str, object]]:
    ioreg = command_path("ioreg")
    if not ioreg:
        return []
    root_class = "IOUSBHostDevice" if kind == "USB" else "IOBluetoothDevice"
    command = [ioreg, "-p", "IOUSB", "-l", "-w", "0"] if kind == "USB" else [ioreg, "-r", "-c", root_class, "-l", "-w", "0"]
    output = command_output(command, timeout=8)
    records: list[dict[str, object]] = []
    for root in parse_ioreg_roots(output, root_class):
        properties = root.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        if kind == "USB":
            name = str(properties.get("USB Product Name") or properties.get("kUSBProductString") or root.get("name") or "").strip()
            manufacturer = properties.get("USB Vendor Name") or properties.get("kUSBVendorString")
            location = properties.get("locationID")
            address = f"location:{location}" if location is not None else None
            if not name:
                continue
            records.append(
                {
                    "kind": "USB",
                    "name": name.split("@", 1)[0].strip(),
                    "manufacturer": manufacturer,
                    "transport": "USB",
                    "address": address,
                    "speed": properties.get("Device Speed") or properties.get("UsbLinkSpeed"),
                    "connected": True,
                }
            )
        else:
            name = str(
                properties.get("BTTTYName")
                or properties.get("BluetoothName")
                or properties.get("Name")
                or root.get("name")
                or ""
            ).strip()
            address = properties.get("BTAddress") or properties.get("BD_ADDR") or properties.get("DeviceAddress")
            if not name or name == "Bluetooth-Incoming-Port":
                continue
            records.append(
                {
                    "kind": "Bluetooth",
                    "name": name,
                    "manufacturer": None,
                    "transport": "Bluetooth",
                    "address": address,
                    "connected": True,
                }
            )
    return records


def peripheral_records(value: object, kind: str, records: list[dict[str, object]]) -> None:
    """Aplati les arbres system_profiler sans exposer les numéros de série."""
    if isinstance(value, dict):
        name = (
            value.get("_name")
            or value.get("device_name")
            or value.get("product_name")
            or value.get("device_product_name")
        )
        if isinstance(name, str) and name.strip() and name not in {"SPUSBDataType", "SPBluetoothDataType"}:
            records.append(
                {
                    "kind": kind,
                    "name": name.strip(),
                    "manufacturer": value.get("manufacturer") or value.get("device_manufacturer") or None,
                    "transport": value.get("transport") or value.get("device_transport") or kind,
                    "address": value.get("device_address") or value.get("address") or None,
                    "connected": True,
                }
            )
        for child in value.values():
            peripheral_records(child, kind, records)
    elif isinstance(value, list):
        for child in value:
            peripheral_records(child, kind, records)


def collect_peripherals() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    peripheral_records(system_profiler_json("SPUSBDataType"), "USB", records)
    peripheral_records(system_profiler_json("SPBluetoothDataType"), "Bluetooth", records)
    if not any(record.get("kind") == "USB" for record in records):
        records.extend(collect_ioreg_peripherals("USB"))
    if not any(record.get("kind") == "Bluetooth" for record in records):
        records.extend(collect_ioreg_peripherals("Bluetooth"))
    unique: dict[tuple[str, str, str], dict[str, object]] = {}
    for record in records:
        key = (str(record["kind"]), str(record["name"]), str(record.get("address") or ""))
        unique[key] = record
    return sorted(unique.values(), key=lambda item: (str(item["kind"]), str(item["name"])))


def build_topology(
    devices: list[dict[str, object]],
    system: dict[str, object],
    selected_interface: Optional[str] = None,
) -> dict[str, object]:
    """Construit une topologie déduite de l'ARP et de la route par défaut."""
    interfaces = system.get("interfaces", [])
    default_interface_name = str(system.get("default_interface") or "")
    local_ip = None
    if isinstance(interfaces, list):
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            if interface.get("name") == default_interface_name and interface.get("ipv4"):
                local_ip = str(interface["ipv4"])
                break
        if local_ip is None:
            for interface in interfaces:
                if isinstance(interface, dict) and interface.get("ipv4") and not interface.get("loopback"):
                    local_ip = str(interface["ipv4"])
                    break

    gateway = default_gateway()
    public_ip = public_ip_address() if gateway else None
    nodes: list[dict[str, object]] = [
        {
            "id": "computer",
            "label": str(system.get("hostname") or "Cet ordinateur"),
            "hostname": system.get("hostname"),
            "kind": "computer",
            "ip": local_ip,
        }
    ]
    edges: list[dict[str, object]] = []
    parent_id = "computer"
    if gateway:
        nodes.append(
            {
                "id": "gateway",
                "label": "Routeur / passerelle",
                "kind": "gateway",
                "ip": gateway,
                "public_ip": public_ip,
            }
        )
        edges.append({"source": "computer", "target": "gateway"})
        parent_id = "gateway"
        nodes.append(
            {
                "id": "internet",
                "label": "Internet",
                "kind": "internet",
                "ip": public_ip,
                "public_ip": public_ip,
            }
        )
        edges.append({"source": "gateway", "target": "internet"})

    seen_ips = {local_ip, gateway}
    visible_devices = [
        device
        for device in devices
        if selected_interface in (None, "", "all") or device.get("interface") == selected_interface
    ]
    for device in visible_devices:
        ip = str(device.get("ip") or "")
        if not ip or ip in seen_ips:
            continue
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        mac = str(device.get("mac") or "").lower().replace("-", ":")
        if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_reserved or mac == "ff:ff:ff:ff:ff:ff":
            continue
        node_id = f"device:{ip}"
        nodes.append(
            {
                "id": node_id,
                "label": str(device.get("hostname") or ip),
                "kind": "device",
                "ip": ip,
                "mac": device.get("mac"),
                "hostname": device.get("hostname"),
                "interface": device.get("interface"),
                "reachable": device.get("reachable"),
                "stale": device.get("stale", False),
                "last_seen": device.get("last_seen"),
            }
        )
        edges.append({"source": parent_id, "target": node_id})
        seen_ips.add(ip)
    return {
        "nodes": nodes,
        "edges": edges,
        "gateway": gateway,
        "public_ip": public_ip,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "device_count": sum(1 for node in nodes if node.get("kind") == "device"),
        "note": "Topologie dynamique : machines actuellement visibles par ARP et appareils vus récemment dans l’historique local. L’IP publique est observée depuis cette connexion ; les liens LAN sont indicatifs.",
    }


def read_recent_events(filename: str, limit: int = 50) -> list[dict[str, object]]:
    if filename.lower() in ("", "none", "-", "off"):
        return []
    path = Path(filename).expanduser()
    if not path.exists():
        return []
    records: deque[dict[str, object]] = deque(maxlen=limit)
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except OSError:
        return []
    return list(reversed(records))


def read_state_summary(filename: str) -> dict[str, object]:
    if filename.lower() in ("", "none", "-", "off"):
        return {"available": False}
    path = Path(filename).expanduser()
    if not path.exists():
        return {"available": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"available": False}
    arp = data.get("arp", {}) if isinstance(data, dict) else {}
    nmap = data.get("nmap", {}) if isinstance(data, dict) else {}
    open_ports = sum(len(entry.get("ports", [])) for entry in nmap.values() if isinstance(entry, dict))
    return {
        "available": True,
        "arp_entries": len(arp) if isinstance(arp, dict) else 0,
        "nmap_hosts": len(nmap) if isinstance(nmap, dict) else 0,
        "nmap_open_ports": open_ports,
    }


def read_cached_hostnames(filename: str) -> dict[str, str]:
    if filename.lower() in ("", "none", "-", "off"):
        return {}
    path = Path(filename).expanduser()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    hostnames = data.get("hostnames", {}) if isinstance(data, dict) else {}
    return {
        str(address): str(name)
        for address, name in hostnames.items()
        if str(address).strip() and str(name).strip()
    } if isinstance(hostnames, dict) else {}


def enrich_device_identities(
    devices: list[dict[str, object]],
    state_file: str,
    resolve_hostnames: bool = False,
) -> list[dict[str, object]]:
    cached = read_cached_hostnames(state_file)
    for device in devices:
        ip = str(device.get("ip") or "")
        hostname = str(device.get("hostname") or "").strip()
        if not hostname or hostname == "?":
            hostname = cached.get(ip, "")
        if not hostname and resolve_hostnames and ip:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (OSError, socket.herror, socket.gaierror):
                hostname = ""
        device["hostname"] = hostname or None
        device["last_seen"] = time.strftime("%H:%M:%S")
    return devices


class HistoryStore:
    """Historique SQLite local, désactivable avec --history-file none."""

    def __init__(self, filename: str) -> None:
        self.path = None if filename.lower() in ("", "none", "-", "off") else Path(filename).expanduser()
        self.lock = threading.RLock()
        self.connection: Optional[sqlite3.Connection] = None
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                cpu_load REAL,
                memory_used_percent REAL,
                network_rx_bytes INTEGER,
                network_tx_bytes INTEGER,
                device_count INTEGER NOT NULL DEFAULT 0,
                connection_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_samples_timestamp ON samples(timestamp);
            CREATE TABLE IF NOT EXISTS network_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                interface TEXT NOT NULL,
                rx_bytes INTEGER,
                tx_bytes INTEGER,
                FOREIGN KEY(sample_id) REFERENCES samples(id)
            );
            CREATE INDEX IF NOT EXISTS idx_network_samples_lookup ON network_samples(interface, timestamp);
            CREATE TABLE IF NOT EXISTS devices (
                device_key TEXT PRIMARY KEY,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                ip TEXT,
                mac TEXT,
                hostname TEXT,
                interface TEXT
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    @property
    def enabled(self) -> bool:
        return self.connection is not None

    @staticmethod
    def device_key(device: dict[str, object]) -> str:
        return str(device.get("mac") or device.get("ip") or "").strip().lower()

    def record_snapshot(self, snapshot: dict[str, object], retention_hours: float) -> list[dict[str, object]]:
        if self.connection is None:
            return []
        system = snapshot.get("system", {})
        cpu = system.get("cpu", {}) if isinstance(system, dict) else {}
        memory = system.get("memory", {}) if isinstance(system, dict) else {}
        network = snapshot.get("network", {})
        load = cpu.get("load", []) if isinstance(cpu, dict) else []
        cpu_load = load[0] if isinstance(load, list) and load else None
        memory_used = memory.get("used_percent") if isinstance(memory, dict) else None
        rx_bytes = network.get("rx_bytes") if isinstance(network, dict) else None
        tx_bytes = network.get("tx_bytes") if isinstance(network, dict) else None
        devices = snapshot.get("devices", [])
        connections = snapshot.get("connections", [])
        now = time.time()
        new_devices: list[dict[str, object]] = []
        with self.lock:
            sample_cursor = self.connection.execute(
                """
                INSERT INTO samples(
                    timestamp, cpu_load, memory_used_percent, network_rx_bytes,
                    network_tx_bytes, device_count, connection_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    cpu_load,
                    memory_used,
                    rx_bytes,
                    tx_bytes,
                    len(devices) if isinstance(devices, list) else 0,
                    len(connections) if isinstance(connections, list) else 0,
                ),
            )
            sample_id = sample_cursor.lastrowid
            if isinstance(network, dict):
                counters = network.get("interfaces", {})
                if isinstance(counters, dict):
                    for interface_name, values in counters.items():
                        if not isinstance(values, dict):
                            continue
                        self.connection.execute(
                            """
                            INSERT INTO network_samples(sample_id, timestamp, interface, rx_bytes, tx_bytes)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (sample_id, now, str(interface_name), values.get("rx_bytes"), values.get("tx_bytes")),
                        )
                if network.get("rx_bytes") is not None or network.get("tx_bytes") is not None:
                    self.connection.execute(
                        """
                        INSERT INTO network_samples(sample_id, timestamp, interface, rx_bytes, tx_bytes)
                        VALUES (?, ?, 'all', ?, ?)
                        """,
                        (sample_id, now, network.get("rx_bytes"), network.get("tx_bytes")),
                    )
            baseline = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'device_baseline_initialized'"
            ).fetchone()
            baseline_initialized = baseline is not None and baseline[0] == "1"
            if isinstance(devices, list):
                for device in devices:
                    if not isinstance(device, dict):
                        continue
                    key = self.device_key(device)
                    if not key:
                        continue
                    known = self.connection.execute(
                        "SELECT 1 FROM devices WHERE device_key = ?", (key,)
                    ).fetchone()
                    if baseline_initialized and known is None:
                        new_devices.append(device)
                    self.connection.execute(
                        """
                        INSERT INTO devices(device_key, first_seen, last_seen, ip, mac, hostname, interface)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(device_key) DO UPDATE SET
                            last_seen = excluded.last_seen,
                            ip = excluded.ip,
                            mac = excluded.mac,
                            hostname = excluded.hostname,
                            interface = excluded.interface
                        """,
                        (
                            key,
                            now,
                            now,
                            device.get("ip"),
                            device.get("mac"),
                            device.get("hostname"),
                            device.get("interface"),
                        ),
                    )
            if not baseline_initialized:
                self.connection.execute(
                    "INSERT OR REPLACE INTO metadata(key, value) VALUES ('device_baseline_initialized', '1')"
                )
            if retention_hours > 0:
                self.connection.execute(
                    "DELETE FROM samples WHERE timestamp < ?", (now - retention_hours * 3600,)
                )
            self.connection.commit()
        return new_devices

    def history(self, hours: float, interface: str = "all", limit: int = 720) -> list[dict[str, object]]:
        if self.connection is None:
            return []
        cutoff = time.time() - max(0, hours) * 3600
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT samples.timestamp, samples.cpu_load, samples.memory_used_percent,
                       CASE WHEN ? = 'all' THEN COALESCE(network_samples.rx_bytes, samples.network_rx_bytes)
                            ELSE network_samples.rx_bytes END,
                       CASE WHEN ? = 'all' THEN COALESCE(network_samples.tx_bytes, samples.network_tx_bytes)
                            ELSE network_samples.tx_bytes END,
                       samples.device_count, samples.connection_count
                FROM samples
                LEFT JOIN network_samples
                    ON network_samples.sample_id = samples.id AND network_samples.interface = ?
                WHERE samples.timestamp >= ?
                ORDER BY samples.timestamp DESC LIMIT ?
                """,
                (interface, interface, interface, cutoff, limit),
            ).fetchall()
        rows = list(reversed(rows))
        return [
            {
                "timestamp": row[0],
                "cpu_load": row[1],
                "memory_used_percent": row[2],
                "network_rx_bytes": row[3],
                "network_tx_bytes": row[4],
                "device_count": row[5],
                "connection_count": row[6],
            }
            for row in rows
        ]

    def known_devices(self, hours: float, limit: int = 500) -> list[dict[str, object]]:
        """Retourne les appareils vus récemment, même s’ils ne sont plus dans l’ARP."""
        if self.connection is None:
            return []
        cutoff = time.time() - max(0, hours) * 3600
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT ip, mac, hostname, interface, last_seen
                FROM devices
                WHERE last_seen >= ?
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        return [
            {
                "ip": row[0],
                "mac": row[1],
                "hostname": row[2],
                "interface": row[3],
                "reachable": False,
                "stale": True,
                "last_seen": time.strftime("%H:%M:%S", time.localtime(row[4])),
            }
            for row in rows
        ]

    def close(self) -> None:
        if self.connection is None:
            return
        with self.lock:
            self.connection.close()
            self.connection = None


def append_event_record(filename: str, rule: str, source: str, message: str) -> None:
    if filename.lower() in ("", "none", "-", "off"):
        return
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "epoch": time.time(),
        "rule": rule,
        "source": source,
        "message": message,
    }
    path = Path(filename).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        return


def applescript_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def notify_macos(title: str, message: str) -> bool:
    osascript = command_path("osascript")
    if not osascript:
        return False
    script = f"display notification {applescript_string(message)} with title {applescript_string(title)}"
    try:
        result = subprocess.run([osascript, "-e", script], capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


class DashboardRuntime:
    def __init__(
        self,
        state_file: str,
        event_log: str,
        history: HistoryStore,
        history_interval: float,
        history_hours: float,
        notify_new_devices: bool,
        resolve_hostnames: bool,
    ) -> None:
        self.state_file = state_file
        self.event_log = event_log
        self.history = history
        self.history_interval = history_interval
        self.history_hours = history_hours
        self.notify_new_devices = notify_new_devices
        self.resolve_hostnames = resolve_hostnames
        self.stop = threading.Event()
        self.snapshot_lock = threading.RLock()
        self.sample_lock = threading.Lock()
        self.latest: Optional[dict[str, object]] = None
        self.thread: Optional[threading.Thread] = None

    def sample_once(self) -> dict[str, object]:
        with self.sample_lock:
            snapshot = collect_snapshot(
                self.state_file,
                self.event_log,
                include_peripherals=True,
                include_topology=True,
                resolve_hostnames=self.resolve_hostnames,
            )
            new_devices = self.history.record_snapshot(snapshot, self.history_hours)
            for device in new_devices:
                label = str(device.get("hostname") or device.get("ip") or "nouvel appareil")
                mac = str(device.get("mac") or "MAC inconnue")
                message = f"{label} détecté ({mac})"
                append_event_record(self.event_log, "NEW_DEVICE", "DASHBOARD", message)
                if self.notify_new_devices:
                    notify_macos("RadarScope — nouvel appareil", message)
            with self.snapshot_lock:
                self.latest = snapshot
            return snapshot

    def loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.sample_once()
            except (OSError, ValueError, sqlite3.Error):
                pass
            self.stop.wait(self.history_interval)

    def start(self) -> None:
        self.thread = threading.Thread(target=self.loop, name="radarscope-history", daemon=True)
        self.thread.start()

    def current(self) -> dict[str, object]:
        with self.snapshot_lock:
            snapshot = self.latest
        return snapshot if snapshot is not None else self.sample_once()

    def response(self, interface: Optional[str] = None) -> dict[str, object]:
        payload = dict(self.current())
        system = payload.get("system", {})
        interface_rows = system.get("interfaces", []) if isinstance(system, dict) else []
        valid_interfaces = {
            str(row.get("name"))
            for row in interface_rows
            if isinstance(row, dict) and row.get("name")
        }
        selected = (interface or "all").strip() or "all"
        if selected != "all" and selected not in valid_interfaces:
            selected = "all"
        devices = payload.get("devices", [])
        if isinstance(devices, list):
            merged_devices: list[dict[str, object]] = []
            seen_keys: set[str] = set()
            for device in devices + self.history.known_devices(self.history_hours):
                if not isinstance(device, dict):
                    continue
                key = str(device.get("mac") or device.get("ip") or "").strip().lower()
                if not key or key in seen_keys:
                    continue
                seen_keys.add(key)
                current_device = dict(device)
                current_device.setdefault("stale", False)
                merged_devices.append(current_device)
            payload["devices"] = [
                device for device in merged_devices if selected == "all" or device.get("interface") == selected
            ]
        payload["network"] = select_network_counters(payload.get("network", {}), selected)
        if isinstance(system, dict):
            payload["topology"] = build_topology(payload.get("devices", []), system, selected)
        payload["selected_interface"] = selected
        payload["available_interfaces"] = interface_rows
        payload["history"] = self.history.history(self.history_hours, selected)
        payload["history_enabled"] = self.history.enabled
        payload["notifications_enabled"] = self.notify_new_devices
        return payload

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=max(2.0, self.history_interval + 1.0))
        self.history.close()


def collect_snapshot(
    state_file: str = DEFAULT_STATE_FILE,
    event_log: str = DEFAULT_EVENT_LOG,
    include_peripherals: bool = False,
    include_topology: bool = False,
    resolve_hostnames: bool = False,
) -> dict[str, object]:
    system = collect_system_snapshot()
    devices = enrich_device_identities(collect_arp_entries(), state_file, resolve_hostnames)
    snapshot: dict[str, object] = {
        "version": VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "system": system,
        "network": collect_network_counters(),
        "devices": devices,
        "connections": collect_connections(),
        "state": read_state_summary(state_file),
        "events": read_recent_events(event_log),
    }
    if include_peripherals:
        snapshot["peripherals"] = collect_peripherals()
    if include_topology:
        snapshot["topology"] = build_topology(devices, system)
    return snapshot


def format_bytes(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "n/d"
    number = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if number < 1024 or unit == "TiB":
            return f"{number:.1f} {unit}" if unit != "B" else f"{number:.0f} B"
        number /= 1024
    return "n/d"


def format_duration(seconds: object) -> str:
    if not isinstance(seconds, (int, float)):
        return "n/d"
    total = max(0, int(seconds))
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days}j {hours:02d}h {minutes:02d}m"
    return f"{hours:02d}h {minutes:02d}m"


def run_status(_context: Context, args: argparse.Namespace) -> int:
    snapshot = collect_snapshot(args.state_file, args.event_log)
    system = snapshot["system"]
    cpu = system["cpu"]
    memory = system["memory"]
    disk = system["disk"]
    battery = system["battery"]
    print(f"RadarScope {VERSION} — {system['hostname']}")
    print(f"Plateforme : {system['platform']}")
    print(f"CPU        : {cpu['cores']} cœur(s), charge {', '.join(map(str, cpu['load'])) or 'n/d'}")
    print(f"Mémoire    : {format_bytes(memory.get('used_bytes'))} / {format_bytes(memory.get('total_bytes'))} ({memory.get('used_percent', 'n/d')}%)")
    print(f"Disque /   : {format_bytes(disk['used_bytes'])} / {format_bytes(disk['total_bytes'])} ({disk['used_percent']}%)")
    print(f"Batterie   : {battery.get('percent', 'n/d')}% — {battery.get('status', 'n/d')}")
    print(f"Uptime     : {format_duration(system['uptime_seconds'])}")
    print(f"Réseau     : {system['default_interface']} — {len(snapshot['devices'])} appareil(s), {len(snapshot['connections'])} connexion(s)")
    return 0


def run_devices(_context: Context, _args: argparse.Namespace) -> int:
    devices = collect_arp_entries()
    if not devices:
        print("Aucun appareil présent dans la table ARP.")
        return 0
    print("IP                 MAC               Interface   État       Nom")
    print("-" * 78)
    for device in devices:
        print(
            f"{str(device['ip']):<18} "
            f"{str(device['mac'] or '-'): <17} "
            f"{str(device['interface']):<11} "
            f"{'actif' if device['reachable'] else 'incomplet':<10} "
            f"{device['hostname'] or '-'}"
        )
    return 0


def run_connections(_context: Context, _args: argparse.Namespace) -> int:
    connections = collect_connections()
    if not connections:
        print("Aucune connexion locale détectée ou lsof est indisponible.")
        return 0
    print("Processus                 PID     Proto  État          Endpoint")
    print("-" * 96)
    for connection in connections:
        process = f"{connection['command']}"
        print(
            f"{process[:24]:<24} {connection['pid']:<7} {connection['protocol']:<6} "
            f"{(connection['state'] or '-'): <12} {connection['endpoint']}"
        )
    return 0


def run_snapshot(_context: Context, args: argparse.Namespace) -> int:
    print(
        json.dumps(
            collect_snapshot(args.state_file, args.event_log, include_peripherals=True, include_topology=True),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


DASHBOARD_HTML = r"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RadarScope — tableau local</title>
  <style>
    :root { color-scheme: dark; --bg:#09111d; --panel:#101d2e; --line:#20334a; --text:#e8f1ff; --muted:#8ca3c0; --cyan:#65dcff; --green:#79e5a0; --yellow:#ffd166; --red:#ff6b7a; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:radial-gradient(circle at top right,#193a53 0,#09111d 42%); color:var(--text); font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { max-width:1440px; margin:0 auto; padding:28px; }
    header { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; margin-bottom:22px; }
    h1 { margin:0 0 5px; font-size:28px; letter-spacing:.02em; } h2 { margin:0 0 14px; font-size:16px; } p { margin:0; color:var(--muted); }
    .badge { border:1px solid #2a5972; color:var(--cyan); border-radius:999px; padding:7px 11px; white-space:nowrap; }
    .grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin-bottom:16px; }
    .card,.panel { background:rgba(16,29,46,.92); border:1px solid var(--line); border-radius:14px; box-shadow:0 14px 32px rgba(0,0,0,.16); }
    .card { padding:16px; min-height:104px; } .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; } .value { margin-top:8px; font-size:22px; font-weight:700; }
    .sub { margin-top:4px; color:var(--muted); font-size:12px; }
    .columns { display:grid; grid-template-columns:1.1fr 1fr; gap:16px; } .panel { padding:18px; margin-bottom:16px; overflow:hidden; }
    table { width:100%; border-collapse:collapse; } th,td { padding:9px 8px; border-bottom:1px solid #1c2c40; text-align:left; vertical-align:top; } th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; } td { font-size:13px; word-break:break-word; } tr:last-child td { border-bottom:0; }
    .ok { color:var(--green); } .warn { color:var(--yellow); } .alert { color:var(--red); } .muted { color:var(--muted); }
    .empty { color:var(--muted); padding:10px 0 2px; } .scroll { max-height:330px; overflow:auto; }
    .charts { display:grid; grid-template-columns:1fr 1fr; gap:16px; } .chart { width:100%; height:220px; display:block; background:#0b1726; border:1px solid #1c2c40; border-radius:10px; }
    .network-controls { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:16px; } .network-controls label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; } select { min-width:280px; padding:9px 10px; border:1px solid #2a4059; border-radius:8px; background:#0b1726; color:var(--text); }
    .filters { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; margin-bottom:12px; }
    input { width:100%; padding:9px 10px; border:1px solid #2a4059; border-radius:8px; background:#0b1726; color:var(--text); outline:none; } input:focus { border-color:var(--cyan); }
    .topology-board { min-height:0; padding:12px; background:#0b1726; border:1px solid #1c2c40; border-radius:10px; overflow:auto; } .topology-route { display:flex; align-items:center; gap:9px; margin-bottom:12px; color:#79a3c7; font-size:18px; } .topology-chip { min-width:150px; padding:7px 10px; border:1px solid #2a3b51; border-radius:7px; background:#102238; color:var(--text); font-size:12px; } .topology-chip.computer { border-color:var(--cyan); } .topology-chip.gateway { border-color:var(--yellow); } .topology-chip.internet { border-color:var(--green); } .topology-chip .muted { display:block; margin-top:2px; } .topology-table { min-width:720px; } .topology-table th, .topology-table td { padding:7px 8px; } .topology-table tr.stale { opacity:.62; } .topology-empty { color:var(--muted); border:1px dashed #2a3b51; border-radius:8px; padding:10px; }
    .machine-map { background:#0b1726; border:1px solid #1c2c40; border-radius:10px; overflow:auto; } .machine-map svg { display:block; width:100%; min-width:760px; height:auto; } .machine-map-link { stroke:#35506b; stroke-width:1.5; opacity:.85; } .machine-map-node rect { fill:#102238; stroke:#2a3b51; stroke-width:1.2; } .machine-map-node.computer rect { stroke:var(--cyan); } .machine-map-node.gateway rect { stroke:var(--yellow); } .machine-map-node.internet rect { stroke:var(--green); } .machine-map-node.device rect { stroke:#5aa6d6; } .machine-map-node.stale { opacity:.62; } .machine-map-globe { fill:none; stroke:var(--green); stroke-width:1.4; } .machine-map-title { fill:var(--text); font-size:12px; font-weight:600; } .machine-map-secondary { fill:var(--cyan); font-size:11px; } .machine-map-detail { fill:var(--muted); font-size:10px; } .machine-map-empty { color:var(--muted); padding:24px 12px; text-align:center; }
    .legend { color:var(--muted); font-size:12px; margin-top:8px; }
    @media (max-width:1000px) { .grid { grid-template-columns:repeat(3,minmax(0,1fr)); } .columns,.charts { grid-template-columns:1fr; } }
    @media (max-width:620px) { main { padding:16px; } header { display:block; } .badge { display:inline-block; margin-top:12px; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .filters { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<main>
  <header><div><h1>RadarScope</h1><p>Vue locale de l’activité autour de cet ordinateur.</p></div><div class="badge" id="updated">Connexion…</div></header>
  <section class="panel network-controls"><label for="interface-select">Interface à observer</label><select id="interface-select"><option value="all">Toutes les interfaces</option></select><span class="legend" id="network-note">—</span></section>
  <section class="grid">
    <article class="card"><div class="label">Charge CPU</div><div class="value" id="cpu">—</div><div class="sub" id="cpu-sub">—</div></article>
    <article class="card"><div class="label">Mémoire</div><div class="value" id="memory">—</div><div class="sub" id="memory-sub">—</div></article>
    <article class="card"><div class="label">Disque /</div><div class="value" id="disk">—</div><div class="sub" id="disk-sub">—</div></article>
    <article class="card"><div class="label">Réseau local</div><div class="value" id="devices">—</div><div class="sub" id="devices-sub">—</div></article>
    <article class="card"><div class="label">Connexions</div><div class="value" id="connections">—</div><div class="sub" id="connections-sub">—</div></article>
  </section>
  <section class="panel"><h2>Historique local</h2><div class="charts"><div><div class="sub">Charge CPU</div><canvas class="chart" id="cpu-chart" width="720" height="220"></canvas></div><div><div class="sub">Débit réseau estimé</div><canvas class="chart" id="network-chart" width="720" height="220"></canvas></div></div><div class="legend" id="history-note">—</div></section>
  <section class="panel"><h2>Carte topologique du réseau local</h2><div class="topology-board" id="topology-view" role="img" aria-label="Topologie réseau"></div><div class="legend" id="topology-note">—</div></section>
  <section class="panel"><h2>Machines autour de cet ordinateur</h2><div class="machine-map" id="machine-map-view" role="img" aria-label="Vue graphique compacte des machines découvertes"></div><div class="legend" id="machine-map-note">—</div></section>
  <div class="columns">
    <div>
      <section class="panel"><h2>Appareils visibles par ARP</h2><div class="scroll" id="devices-table"></div></section>
      <section class="panel"><h2>Interfaces réseau</h2><div class="scroll" id="interfaces-table"></div></section>
      <section class="panel"><h2>USB et Bluetooth</h2><div class="scroll" id="peripherals-table"></div></section>
    </div>
    <div>
      <section class="panel"><h2>Connexions et processus</h2><div class="filters"><input id="filter-app" placeholder="Filtrer par application"><input id="filter-port" placeholder="Filtrer par port"><input id="filter-remote" placeholder="Filtrer par adresse distante"></div><div class="sub" id="connections-count"></div><div class="scroll" id="connections-table"></div></section>
      <section class="panel"><h2>Alertes récentes</h2><div class="scroll" id="events-table"></div></section>
    </div>
  </div>
</main>
<script>
const esc = value => String(value ?? "—").replace(/[&<>\"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));
const bytes = value => { if (value == null) return "n/d"; const units=["B","KiB","MiB","GiB","TiB"]; let n=Number(value), i=0; while(n>=1024&&i<units.length-1){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${units[i]}`; };
const table = (headers, rows, empty) => rows.length ? `<table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>` : `<div class="empty">${esc(empty)}</div>`;
let selectedInterface = new URLSearchParams(window.location.search).get("interface") || "all";
let latestData = null;
function renderInterfaceSelector(data) {
  const select = document.getElementById("interface-select"), rows = (data.system && data.system.interfaces) || [], previous = selectedInterface;
  const options = ["<option value=\"all\">Toutes les interfaces</option>"].concat(rows.filter(row => row.name && row.selectable).map(row => "<option value=\"" + esc(row.name) + "\">" + esc((row.hardware_port || row.name) + " · " + (row.kind || "réseau") + (row.ipv4 ? " · " + row.ipv4 : "") + (row.active ? " · active" : " · déconnectée")) + "</option>"));
  select.innerHTML = options.join("");
  select.value = previous;
  if (select.value !== previous) { selectedInterface = "all"; select.value = "all"; }
}
function drawChart(canvasId, values, color, suffix) {
  const canvas = document.getElementById(canvasId);
  const width = canvas.clientWidth || 720, height = canvas.clientHeight || 220, dpr = window.devicePixelRatio || 1;
  canvas.width = width * dpr; canvas.height = height * dpr;
  const ctx = canvas.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, width, height);
  const clean = values.map(Number).filter(Number.isFinite);
  if (!clean.length) { ctx.fillStyle = "#8ca3c0"; ctx.fillText("Pas encore assez de données", 16, 28); return; }
  const min = Math.min.apply(null, clean), max = Math.max.apply(null, clean), span = Math.max(max - min, 0.01), pad = 22;
  ctx.strokeStyle = "#20334a"; ctx.lineWidth = 1;
  for (let i = 0; i < 4; i++) { const y = pad + (height - pad * 1.5) * i / 3; ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(width - pad, y); ctx.stroke(); }
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
  values.forEach((value, index) => { const x = pad + (width - pad * 2) * index / Math.max(1, values.length - 1); const number = Number(value); const y = height - pad - (Number.isFinite(number) ? (number - min) / span : 0) * (height - pad * 1.8); index ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.stroke(); ctx.fillStyle = "#8ca3c0"; ctx.font = "11px -apple-system,BlinkMacSystemFont,sans-serif"; ctx.fillText(max.toFixed(2) + suffix, pad, 12); ctx.fillText(min.toFixed(2) + suffix, pad, height - 4);
}
function networkRates(history, field) {
  return history.map((item, index) => { if (index === 0 || item[field] == null || history[index - 1][field] == null) return 0; const seconds = Math.max(1, Number(item.timestamp) - Number(history[index - 1].timestamp)); return Math.max(0, (Number(item[field]) - Number(history[index - 1][field])) / seconds / 1024 / 1024); });
}
function renderConnections(data) {
  const app = document.getElementById("filter-app").value.trim().toLowerCase(), port = document.getElementById("filter-port").value.trim().toLowerCase(), remote = document.getElementById("filter-remote").value.trim().toLowerCase();
  const all = data.connections || [], filtered = all.filter(connection => { const text = String(connection.command) + " " + String(connection.protocol) + " " + String(connection.endpoint) + " " + String(connection.local || "") + " " + String(connection.remote || ""); return (!app || String(connection.command).toLowerCase().includes(app)) && (!port || text.toLowerCase().includes(port)) && (!remote || String(connection.remote || "").toLowerCase().includes(remote)); });
  document.getElementById("connections-count").textContent = filtered.length + " / " + all.length + " connexion(s)";
  document.getElementById("connections-table").innerHTML = table(["Processus", "Proto", "État", "Endpoint"], filtered.map(connection => "<tr><td>" + esc(connection.command) + " <span class=\"muted\">(" + esc(connection.pid) + ")</span></td><td>" + esc(connection.protocol) + "</td><td>" + esc(connection.state || "—") + "</td><td>" + esc(connection.endpoint) + "</td></tr>"), "Aucune connexion ne correspond aux filtres.");
}
function renderTopology(topology) {
  const view = document.getElementById("topology-view"), nodes = topology.nodes || [];
  const computer = nodes.find(node => node.kind === "computer"), gateway = nodes.find(node => node.kind === "gateway"), internet = nodes.find(node => node.kind === "internet"), devices = nodes.filter(node => node.kind === "device");
  const chip = (node, kind) => {
    if (!node) return `<div class="topology-chip"><span class="muted">Non déterminée</span></div>`;
    const title = kind === "internet" ? "🌐 Internet" : node.hostname || node.label || "Inconnu";
    const address = kind === "internet" ? node.public_ip || "IP publique indisponible" : node.ip || "IP inconnue";
    const publicLine = kind === "gateway" ? `<span class="muted">IP publique : ${esc(node.public_ip || "indisponible")}</span>` : "";
    return `<div class="topology-chip ${kind}">${esc(title)}<span class="muted">${esc(address)}</span>${publicLine}</div>`;
  };
  const rows = devices.map(node => `<tr class="${node.stale ? "stale" : ""}"><td>${esc(node.label || node.ip || "Machine")}</td><td>${esc(node.hostname || "—")}</td><td>${esc(node.ip || "—")}</td><td>${esc(node.mac || "—")}</td><td>${esc(node.interface || "—")}</td><td class="${node.stale ? "muted" : "ok"}">${node.stale ? "vue récemment" : "présente"}</td><td>${esc(node.last_seen || "—")}</td></tr>`).join("");
  const internetLink = internet ? `<span>→</span>${chip(internet, "internet")}` : "";
  view.innerHTML = `<div class="topology-route">${chip(computer, "computer")}<span>→</span>${chip(gateway, "gateway")}${internetLink}</div>${devices.length ? `<div class="scroll"><table class="topology-table"><thead><tr><th>Nom affiché</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Interface</th><th>État</th><th>Dernière vue</th></tr></thead><tbody>${rows}</tbody></table></div>` : "<div class=\"topology-empty\">Aucune autre machine visible par ARP ou dans l’historique récent.</div>"}`;
  document.getElementById("topology-note").textContent = topology.note || "Topologie indisponible.";
}
function renderMachineMap(topology) {
  const view = document.getElementById("machine-map-view"), nodes = topology.nodes || [], edges = topology.edges || [];
  const computer = nodes.find(node => node.kind === "computer"), gateway = nodes.find(node => node.kind === "gateway"), internet = nodes.find(node => node.kind === "internet"), devices = nodes.filter(node => node.kind === "device");
  if (!nodes.length) { view.innerHTML = "<div class=\"machine-map-empty\">Aucune machine découverte pour le moment.</div>"; document.getElementById("machine-map-note").textContent = "Vue graphique indisponible."; return; }
  const cardW = 180, cardH = 72, columnGap = 18, rowGap = 14, columns = Math.min(3, Math.max(1, devices.length)), rows = Math.max(1, Math.ceil(devices.length / columns));
  const deviceAreaW = columns * cardW + (columns - 1) * columnGap, deviceAreaH = rows * cardH + (rows - 1) * rowGap, flowBlockH = internet ? cardH * 2 + 24 : cardH, height = Math.max(184, deviceAreaH + 40, flowBlockH + 40), flowY = Math.max(20, (height - flowBlockH) / 2);
  const computerX = 24, gatewayX = 244, internetX = gatewayX, flowEnd = gatewayX + cardW, deviceX = devices.length ? Math.max(650, flowEnd + 28) : flowEnd + 24, width = Math.max(760, deviceX + (devices.length ? deviceAreaW : 0) + 24), positions = {};
  const gatewayY = flowY + (internet ? cardH + 24 : 0);
  if (computer) positions[computer.id] = {x: computerX, y: gatewayY};
  if (gateway) positions[gateway.id] = {x: gatewayX, y: gatewayY};
  if (internet) positions[internet.id] = {x: internetX, y: flowY};
  devices.forEach((node, index) => { positions[node.id] = {x: deviceX + (index % columns) * (cardW + columnGap), y: 20 + Math.floor(index / columns) * (cardH + rowGap)}; });
  const shorten = (value, limit) => { const text = String(value ?? "—"); return text.length > limit ? text.slice(0, limit - 1) + "…" : text; };
  const nodeSvg = (node, kind) => {
    const position = positions[node.id], status = node.stale ? "vue récemment" : kind === "device" ? "présente" : kind === "gateway" ? "passerelle" : "local";
    const title = kind === "internet" ? "Internet" : node.hostname || node.label || (kind === "device" ? "Machine" : "Inconnu");
    const address = kind === "internet" ? node.public_ip || "IP publique indisponible" : node.ip || "IP inconnue";
    const detail = kind === "device" ? `${node.mac || "MAC inconnue"} · ${node.interface || "interface inconnue"} · ${status}` : kind === "gateway" ? `IP publique : ${node.public_ip || "indisponible"}` : kind === "internet" ? "sortie Internet" : status;
    const titleX = kind === "internet" ? 42 : 12, secondaryX = kind === "internet" ? 42 : 12, detailX = kind === "internet" ? 42 : 12, globe = kind === "internet" ? `<circle class="machine-map-globe" cx="22" cy="36" r="12"></circle><path class="machine-map-globe" d="M10 36h24M22 24c4 4 4 20 0 24M22 24c-4 4-4 20 0 24"></path>` : "";
    return `<g class="machine-map-node ${kind} ${node.stale ? "stale" : ""}" transform="translate(${position.x},${position.y})"><title>${esc(`${title} · ${address} · ${detail}`)}</title><rect width="${cardW}" height="${cardH}" rx="9"></rect>${globe}<text class="machine-map-title" x="${titleX}" y="21">${esc(shorten(title, 22))}</text><text class="machine-map-secondary" x="${secondaryX}" y="40">${esc(shorten(address, 25))}</text><text class="machine-map-detail" x="${detailX}" y="59">${esc(shorten(detail, 30))}</text></g>`;
  };
  const links = edges.map(edge => {
    const from = positions[edge.source], to = positions[edge.target];
    if (!from || !to) return "";
    if (internet && edge.source === gateway?.id && edge.target === internet.id) {
      return `<line class="machine-map-link" x1="${from.x + cardW / 2}" y1="${from.y}" x2="${to.x + cardW / 2}" y2="${to.y + cardH}"></line>`;
    }
    return `<line class="machine-map-link" x1="${from.x + cardW}" y1="${from.y + cardH / 2}" x2="${to.x}" y2="${to.y + cardH / 2}"></line>`;
  }).join("");
  view.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Machines connectées ou récemment découvertes"><g>${links}</g>${computer ? nodeSvg(computer, "computer") : ""}${gateway ? nodeSvg(gateway, "gateway") : ""}${internet ? nodeSvg(internet, "internet") : ""}${devices.map(node => nodeSvg(node, "device")).join("")}</svg>`;
  document.getElementById("machine-map-note").textContent = devices.length ? `${devices.length} machine(s) représentée(s) · mise à jour automatique avec les nouvelles découvertes` : "Ordinateur local et passerelle affichés ; aucune autre machine découverte.";
}
function renderExtras(data) {
  latestData = data;
  const history = data.history || [], hasNetworkHistory = history.some(item => item.network_rx_bytes != null || item.network_tx_bytes != null), rx = hasNetworkHistory ? networkRates(history, "network_rx_bytes") : [], tx = hasNetworkHistory ? networkRates(history, "network_tx_bytes") : [];
  drawChart("cpu-chart", history.map(item => item.cpu_load), "#65dcff", "");
  drawChart("network-chart", rx.map((value, index) => value + (tx[index] || 0)), "#79e5a0", " MiB/s");
  document.getElementById("history-note").textContent = data.history_enabled ? history.length + " points conservés localement dans SQLite" : "Historique désactivé";
  renderTopology(data.topology || {}); renderMachineMap(data.topology || {}); renderConnections(data);
}
const update = async () => {
  try {
    const data = await fetch(`/api/snapshot?interface=${encodeURIComponent(selectedInterface)}&ts=${Date.now()}`, {cache:"no-store"}).then(response => response.json());
    renderInterfaceSelector(data);
    const s=data.system, cpu=s.cpu, mem=s.memory, disk=s.disk;
    document.getElementById("updated").textContent=`Actualisé ${new Date().toLocaleTimeString()}`;
    document.getElementById("cpu").textContent=cpu.load.length ? `${cpu.load[0]} / ${cpu.load[1] ?? "—"}` : "n/d";
    document.getElementById("cpu-sub").textContent=`${cpu.cores} cœur(s)`;
    document.getElementById("memory").textContent=mem.used_percent == null ? "n/d" : `${mem.used_percent}%`;
    document.getElementById("memory-sub").textContent=`${bytes(mem.used_bytes)} / ${bytes(mem.total_bytes)}`;
    document.getElementById("disk").textContent=`${disk.used_percent}%`;
    document.getElementById("disk-sub").textContent=`${bytes(disk.free_bytes)} libres`;
    document.getElementById("devices").textContent=data.devices.length;
    document.getElementById("devices-sub").textContent=`interface ${esc(s.default_interface)}`;
    document.getElementById("connections").textContent=data.connections.length;
    document.getElementById("connections-sub").textContent=`uptime ${esc(s.uptime_seconds == null ? "n/d" : Math.floor(s.uptime_seconds/3600)+"h")}`;
    document.getElementById("network-note").textContent=data.network && data.network.available ? `Débit estimé · ${data.network.source || "compteurs macOS"} · ${data.network.selected_interface === "all" ? "toutes les interfaces" : data.network.selected_interface}` : "Compteurs réseau indisponibles sur cette machine ou cette interface";
    document.getElementById("devices-table").innerHTML=table(["Nom connu","IP","MAC","Interface","Dernière vue","État"], data.devices.map(d=>`<tr><td>${esc(d.hostname || "inconnu")}</td><td>${esc(d.ip)}</td><td>${esc(d.mac || "—")}</td><td>${esc(d.interface)}</td><td>${esc(d.last_seen || "—")}</td><td class="${d.reachable?"ok":"warn"}">${d.reachable?"actif":"incomplet"}</td></tr>`), "La table ARP est vide.");
    document.getElementById("interfaces-table").innerHTML=table(["Interface","Type","IPv4","État"], s.interfaces.map(i=>`<tr><td>${esc(i.hardware_port || i.name)}</td><td>${esc(i.kind || "réseau")}</td><td>${esc(i.ipv4 || "—")}</td><td class="${i.active?"ok":"muted"}">${i.active?"active":"inactive"}</td></tr>`), "Aucune interface détectée.");
    document.getElementById("connections-table").innerHTML=table(["Processus","Proto","État","Endpoint"], data.connections.map(c=>`<tr><td>${esc(c.command)} <span class="muted">(${esc(c.pid)})</span></td><td>${esc(c.protocol)}</td><td>${esc(c.state || "—")}</td><td>${esc(c.endpoint)}</td></tr>`), "Aucune connexion ou lsof est indisponible.");
    document.getElementById("events-table").innerHTML=table(["Heure","Règle","Message"], data.events.map(e=>`<tr><td>${esc(e.timestamp)}</td><td class="${e.rule && String(e.rule).includes("NEW") ? "alert" : "warn"}">${esc(e.rule)}</td><td>${esc(e.message)}</td></tr>`), "Aucune alerte récente.");
    document.getElementById("peripherals-table").innerHTML=table(["Type","Nom","Fabricant","Adresse / emplacement","État"], (data.peripherals||[]).map(p=>"<tr><td>"+esc(p.kind)+"</td><td>"+esc(p.name)+"</td><td>"+esc(p.manufacturer||"—")+"</td><td>"+esc(p.address||"—")+"</td><td class=\""+(p.connected?"ok":"muted")+"\">"+(p.connected?"détecté":"non connecté")+"</td></tr>"), "Aucun périphérique USB ou Bluetooth détecté.");
    renderExtras(data);
  } catch (error) { document.getElementById("updated").textContent="Dashboard indisponible"; }
};
["filter-app","filter-port","filter-remote"].forEach(id=>document.getElementById(id).addEventListener("input",()=>latestData&&renderConnections(latestData)));
document.getElementById("interface-select").addEventListener("change", event=>{selectedInterface=event.target.value;const url=new URL(window.location.href);if(selectedInterface==="all")url.searchParams.delete("interface");else url.searchParams.set("interface",selectedInterface);window.history.replaceState({}, "", url);update();});
update(); setInterval(update, 3000);
</script>
</body>
</html>"""


def dashboard_handler(runtime: DashboardRuntime) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"RadarScope/{VERSION}"

        def do_GET(self) -> None:  # noqa: N802 - nom imposé par BaseHTTPRequestHandler
            parsed_url = urlparse(self.path)
            route = parsed_url.path
            if route == "/":
                payload = DASHBOARD_HTML.encode("utf-8")
                content_type = "text/html; charset=utf-8"
            elif route == "/api/snapshot":
                query = parse_qs(parsed_url.query)
                interface = query.get("interface", ["all"])[0]
                payload = json.dumps(runtime.response(interface), ensure_ascii=False).encode("utf-8")
                content_type = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def run_dashboard(context: Context, args: argparse.Namespace) -> int:
    if not 1 <= args.port <= 65535:
        raise ValueError("--port doit être compris entre 1 et 65535")
    host = args.host.strip()
    if not host:
        raise ValueError("--host ne peut pas être vide")
    url_host = "[::1]" if host == "::1" else host
    url = f"http://{url_host}:{args.port}/"
    context.section("RADARSCOPE / DASHBOARD")
    context.emit("info", "WEB", f"adresse locale : {url}")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        context.emit("warn", "WEB", "le dashboard sera accessible depuis d'autres machines")
    if args.history_interval <= 0:
        raise ValueError("--history-interval doit être supérieur à 0")
    if args.history_hours < 0:
        raise ValueError("--history-hours ne peut pas être négatif")
    if args.dry_run:
        context.emit("dim", "WEB", "mode simulation : aucun serveur ne sera lancé")
        return 0
    try:
        history = HistoryStore(args.history_file)
        runtime = DashboardRuntime(
            args.state_file,
            args.event_log,
            history,
            args.history_interval,
            args.history_hours,
            args.notify_new_devices,
            args.resolve_hostnames,
        )
    except (OSError, sqlite3.Error) as exc:
        raise ValueError(f"impossible d'ouvrir l'historique SQLite : {exc}") from exc
    try:
        server = ThreadingHTTPServer((host, args.port), dashboard_handler(runtime))
    except OSError as exc:
        history.close()
        raise ValueError(f"impossible d'ouvrir {url} : {exc}") from exc
    server.daemon_threads = True
    runtime.start()
    context.emit("ok", "WEB", "dashboard actif ; Ctrl-C pour arrêter")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        context.emit("info", "WEB", "arrêt demandé")
    finally:
        server.server_close()
        runtime.close()
    return 0


def manual_text() -> str:
    return f"""\
RADARSCOPE(1)                 Utilitaires réseau                 RADARSCOPE(1)

NOM
    radarscope - observe un réseau local en temps réel avec nmap, arp et tcpdump

SYNOPSIS
    radarscope.py <commande> [options]

DESCRIPTION
    Outil de rappel et de supervision réseau locale pour macOS. Les sorties de
    nmap, arp et tcpdump sont relayées au fil de l'eau. Les événements considérés
    suspects sont affichés en rouge : ports sensibles ouverts, entrées ARP sans réponse
    (regroupées en avertissement), changements IP/MAC confirmés, nouveaux ports ouverts, scans
    multiports et connexions TCP vers des ports sensibles. L'état est conservé
    dans un fichier JSON et les alertes dans un journal JSONL. Les associations
    complètes sont rappelées sous la forme « IDENTITY host=nom (IP) mac=... ».
    Ces règles sont heuristiques et ne constituent pas un diagnostic de sécurité.

COMMANDES
    doctor       Vérifie la présence de nmap, arp et tcpdump.
    status       Affiche l'état de l'ordinateur et du réseau local.
    devices      Affiche les appareils présents dans la table ARP.
    connections  Affiche les connexions et processus locaux.
    snapshot     Exporte un état complet au format JSON.
    dashboard    Lance un tableau de bord web local, actualisé automatiquement.
    scan         Lance un scan nmap ponctuel.
    arp          Affiche la table ARP ponctuellement.
    capture      Suit tcpdump jusqu'à Ctrl-C ou --count.
    watch        Lance les trois flux en parallèle et répète arp/nmap.
    reset-hostnames
                 Vide le cache hostname/MAC sans toucher aux baselines.
    man          Affiche cette page de rappel.

OPTIONS PRINCIPALES
    --color {{auto,always,never}}   Couleurs truecolor ANSI (défaut : auto).
    --display compact|raw           Affichage résumé ou lignes originales
                                    (défaut : compact).
    --suspicious-ports LISTE        Ports rouges, ex. 23,445,3389 (défaut :
                                    {DEFAULT_SUSPICIOUS_PORTS}).
    --target CIBLE                  IP, nom d'hôte ou CIDR nmap (défaut :
                                    {DEFAULT_TARGET}).
    --ports LISTE                   Ports/ranges nmap, ex. 22,80,443,8000-8100.
    --interface NOM                 Interface tcpdump (défaut : interface par défaut).
    --filter EXPRESSION             Filtre tcpdump (défaut : "{DEFAULT_CAPTURE_FILTER}").
    --buffer-kib N                  Taille du buffer de capture (défaut :
                                    {DEFAULT_TCPDUMP_BUFFER_KIB} KiB).
    --timing 3|4                    Vitesse Nmap ; T4 convient à un LAN fiable,
                                    T3 reste le choix prudent.
    --resolve-hostnames              Résout les noms au premier scan avec Nmap (-R),
                                    puis réutilise le cache enregistré dans l’état.
    --sudo-tcpdump                  Préfixe tcpdump par sudo si les droits sont requis.
    --dry-run                       Affiche les commandes sans les exécuter.

OBSERVATION LOCALE
    status       CPU, mémoire, disque, batterie, uptime et compteurs réseau.
    devices      Appareils connus par la table ARP, sans lancer de scan actif.
    connections  Connexions TCP/UDP visibles par lsof et processus associés.
    snapshot     Même état sous forme JSON, pour automatisation ou archivage.
    dashboard    Interface locale sur 127.0.0.1:8765 ; aucune dépendance web.
                 --host permet une autre adresse d'écoute, à utiliser avec prudence.
                 --history-file / --history-hours contrôlent SQLite et sa rétention.
                 --notify-new-devices active les notifications macOS opt-in.

SURVEILLANCE ET HISTORIQUE (watch)
    --state-file PATH               Historique JSON (défaut : radarscope_state.json).
                                    Utilisé aussi par reset-hostnames.
    --event-log PATH                Alertes JSONL (défaut : radarscope_events.jsonl).
    --allow-host IP                 IP connue à ignorer ; option répétable.
    --confirmations N               Observations nécessaires avant une alerte de
                                    changement (défaut : 2).
    --alert-cooldown SEC            Délai avant de répéter la même alerte (120 s).
    --scan-window SEC               Fenêtre glissante des scans (10 s).
    --arp-interval SEC              Intervalle des relevés ARP (défaut : 10 s).
    --scan-interval SEC             Intervalle des scans Nmap (défaut : 30 s).
    --scan-ports-threshold N        Ports distincts avant alerte (20).
    --scan-hosts-threshold N        Hôtes distincts avant alerte (10).
    --stealth-threshold N           Ports FIN/NULL distincts avant alerte (5).

EXEMPLES
    radarscope.py doctor
    radarscope.py scan --target 127.0.0.1 --ports 22,80,443
    radarscope.py scan --target 192.168.1.0/24 --resolve-hostnames
    radarscope.py reset-hostnames
    radarscope.py capture --interface en0 --filter "tcp or arp" --sudo-tcpdump
    radarscope.py watch --interface en0 --target 192.168.1.0/24 --color always
    radarscope.py watch --target 192.168.1.0/24 --resolve-hostnames
    radarscope.py watch --target 192.168.1.0/24 --scan-interval 60 --duration 300 \\
        --allow-host 192.168.1.1 --state-file radarscope_state.json

CODES COULEUR
    vert       information normale / port détecté
    jaune      avertissement / tentative TCP SYN
    rouge      événement correspondant à une règle suspecte

NOTES
    Utilise --target uniquement sur un réseau que tu administres ou pour lequel
    tu as une autorisation. tcpdump peut nécessiter sudo sur macOS. Le programme
    n'inspecte pas le contenu des paquets : il limite la capture aux en-têtes.
    Le premier lancement crée la baseline ; les changements sont alertés ensuite.

VERSION
    {VERSION}
"""


def add_common_arguments(parser: argparse.ArgumentParser, suppress_defaults: bool = False) -> None:
    default = argparse.SUPPRESS if suppress_defaults else "auto"
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default=default,
        help="couleurs truecolor ANSI (défaut : auto)",
    )
    display_default = argparse.SUPPRESS if suppress_defaults else "compact"
    parser.add_argument(
        "--display",
        choices=("compact", "raw"),
        default=display_default,
        help="format d'affichage : compact ou lignes originales (défaut : compact)",
    )
    suspicious_default = argparse.SUPPRESS if suppress_defaults else DEFAULT_SUSPICIOUS_PORTS
    parser.add_argument(
        "--suspicious-ports",
        default=suspicious_default,
        metavar="LISTE",
        help=f"ports signalés en rouge (défaut : {DEFAULT_SUSPICIOUS_PORTS})",
    )
    dry_default = argparse.SUPPRESS if suppress_defaults else False
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=dry_default,
        help="affiche les commandes sans les exécuter",
    )


def add_detection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        metavar="PATH",
        help=f"historique JSON pour les comparaisons (défaut : {DEFAULT_STATE_FILE}; none = désactivé)",
    )
    parser.add_argument(
        "--event-log",
        default=DEFAULT_EVENT_LOG,
        metavar="PATH",
        help=f"journal JSONL des alertes (défaut : {DEFAULT_EVENT_LOG}; none = désactivé)",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="IP",
        help="IP(s) à ne pas alerter ; option répétable ou séparée par des virgules",
    )
    parser.add_argument(
        "--confirmations",
        type=int,
        default=DEFAULT_CONFIRMATIONS,
        metavar="N",
        help=f"observations avant alerte de changement (défaut : {DEFAULT_CONFIRMATIONS})",
    )
    parser.add_argument(
        "--alert-cooldown",
        type=float,
        default=DEFAULT_ALERT_COOLDOWN,
        metavar="SEC",
        help=f"délai anti-répétition des alertes (défaut : {DEFAULT_ALERT_COOLDOWN:g}s)",
    )
    parser.add_argument(
        "--scan-window",
        type=float,
        default=DEFAULT_SCAN_WINDOW,
        metavar="SEC",
        help=f"fenêtre de détection des scans (défaut : {DEFAULT_SCAN_WINDOW:g}s)",
    )
    parser.add_argument(
        "--scan-ports-threshold",
        type=int,
        default=DEFAULT_SCAN_PORT_THRESHOLD,
        metavar="N",
        help=f"ports distincts avant alerte (défaut : {DEFAULT_SCAN_PORT_THRESHOLD})",
    )
    parser.add_argument(
        "--scan-hosts-threshold",
        type=int,
        default=DEFAULT_SCAN_HOST_THRESHOLD,
        metavar="N",
        help=f"hôtes distincts avant alerte (défaut : {DEFAULT_SCAN_HOST_THRESHOLD})",
    )
    parser.add_argument(
        "--stealth-threshold",
        type=int,
        default=DEFAULT_STEALTH_THRESHOLD,
        metavar="N",
        help=f"ports FIN/NULL distincts avant alerte (défaut : {DEFAULT_STEALTH_THRESHOLD})",
    )


def add_snapshot_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        metavar="PATH",
        help=f"historique JSON à résumer (défaut : {DEFAULT_STATE_FILE})",
    )
    parser.add_argument(
        "--event-log",
        default=DEFAULT_EVENT_LOG,
        metavar="PATH",
        help=f"journal JSONL à afficher (défaut : {DEFAULT_EVENT_LOG})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="radarscope.py",
        description="Surveillance réseau locale macOS avec sortie temps réel et couleurs RGB.",
        epilog="Conseil : commence par « radarscope.py doctor », puis « radarscope.py man ».",
    )
    add_common_arguments(parser)
    parser.add_argument("--version", action="version", version=f"radarscope {VERSION}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMANDE")

    common_sub = argparse.ArgumentParser(add_help=False)
    add_common_arguments(common_sub, suppress_defaults=True)

    doctor = subparsers.add_parser("doctor", parents=[common_sub], help="vérifie les outils disponibles")
    doctor.set_defaults(handler=run_doctor)

    status = subparsers.add_parser("status", parents=[common_sub], help="affiche l'état de l'ordinateur")
    add_snapshot_arguments(status)
    status.set_defaults(handler=run_status)

    devices = subparsers.add_parser("devices", parents=[common_sub], help="affiche les appareils ARP visibles")
    devices.set_defaults(handler=run_devices)

    connections = subparsers.add_parser(
        "connections", parents=[common_sub], help="affiche les connexions et processus locaux"
    )
    connections.set_defaults(handler=run_connections)

    snapshot = subparsers.add_parser("snapshot", parents=[common_sub], help="exporte un état JSON complet")
    add_snapshot_arguments(snapshot)
    snapshot.set_defaults(handler=run_snapshot)

    dashboard = subparsers.add_parser(
        "dashboard", parents=[common_sub], help="lance le tableau de bord web local"
    )
    dashboard.add_argument("--host", default=DEFAULT_DASHBOARD_HOST, help="adresse d'écoute (défaut : 127.0.0.1)")
    dashboard.add_argument("--port", type=int, default=DEFAULT_DASHBOARD_PORT, help=f"port HTTP (défaut : {DEFAULT_DASHBOARD_PORT})")
    dashboard.add_argument("--history-file", default=DEFAULT_HISTORY_FILE, metavar="PATH", help=f"base SQLite locale (défaut : {DEFAULT_HISTORY_FILE}; none = désactivée)")
    dashboard.add_argument("--history-interval", type=float, default=DEFAULT_HISTORY_INTERVAL, metavar="SEC", help=f"fréquence de mesure (défaut : {DEFAULT_HISTORY_INTERVAL:g}s)")
    dashboard.add_argument("--history-hours", type=float, default=DEFAULT_HISTORY_HOURS, metavar="HEURES", help=f"rétention des mesures (défaut : {DEFAULT_HISTORY_HOURS:g}h)")
    dashboard.add_argument("--notify-new-devices", action="store_true", help="active les notifications macOS pour les nouveaux appareils")
    dashboard.add_argument("--resolve-hostnames", action="store_true", help="tente de résoudre les noms DNS des appareils découverts")
    add_snapshot_arguments(dashboard)
    dashboard.set_defaults(handler=run_dashboard)

    scan = subparsers.add_parser("scan", parents=[common_sub], help="lance un scan nmap ponctuel")
    scan.add_argument("--target", default=DEFAULT_TARGET, help="IP, nom d'hôte ou CIDR")
    scan.add_argument("--ports", default=DEFAULT_PORTS, metavar="LISTE", help="ports ou ranges à tester")
    scan.add_argument("--timing", type=int, choices=(3, 4), default=3, metavar="3|4", help="timing Nmap (défaut : T3)")
    scan.add_argument("--resolve-hostnames", action="store_true", help="force la résolution DNS inverse pour Nmap")
    scan.set_defaults(handler=run_scan)

    arp = subparsers.add_parser("arp", parents=[common_sub], help="affiche la table ARP")
    arp.set_defaults(handler=run_arp)

    capture = subparsers.add_parser("capture", parents=[common_sub], help="suit tcpdump en temps réel")
    capture.add_argument("--interface", default=default_interface(), help="interface réseau")
    capture.add_argument("--filter", default=DEFAULT_CAPTURE_FILTER, metavar="EXPRESSION", help="expression de filtre tcpdump")
    capture.add_argument("--count", type=int, metavar="N", help="arrête après N paquets")
    capture.add_argument("--buffer-kib", type=int, default=DEFAULT_TCPDUMP_BUFFER_KIB, metavar="N", help="buffer de capture en KiB")
    capture.add_argument("--sudo-tcpdump", action="store_true", help="lance tcpdump via sudo")
    capture.set_defaults(handler=run_capture)

    watch = subparsers.add_parser("watch", parents=[common_sub], help="surveille arp, nmap et tcpdump")
    watch.add_argument("--interface", default=default_interface(), help="interface réseau pour tcpdump")
    watch.add_argument("--target", default=DEFAULT_TARGET, help="cible nmap : IP, nom d'hôte ou CIDR")
    watch.add_argument("--ports", default=DEFAULT_PORTS, metavar="LISTE", help="ports ou ranges nmap")
    watch.add_argument("--filter", default=DEFAULT_CAPTURE_FILTER, metavar="EXPRESSION", help="expression de filtre tcpdump")
    watch.add_argument("--sudo-tcpdump", action="store_true", help="lance tcpdump via sudo")
    watch.add_argument("--count", type=int, metavar="N", help="arrête tcpdump après N paquets")
    watch.add_argument("--buffer-kib", type=int, default=DEFAULT_TCPDUMP_BUFFER_KIB, metavar="N", help="buffer de capture en KiB")
    watch.add_argument("--timing", type=int, choices=(3, 4), default=3, metavar="3|4", help="timing Nmap (défaut : T3)")
    watch.add_argument("--resolve-hostnames", action="store_true", help="force la résolution DNS inverse pour Nmap")
    watch.add_argument("--arp-interval", type=float, default=DEFAULT_ARP_INTERVAL, metavar="SEC", help=f"intervalle arp (défaut : {DEFAULT_ARP_INTERVAL:g}s)")
    watch.add_argument("--scan-interval", type=float, default=DEFAULT_SCAN_INTERVAL, metavar="SEC", help=f"intervalle nmap (défaut : {DEFAULT_SCAN_INTERVAL:g}s)")
    watch.add_argument("--duration", type=float, default=0, metavar="SEC", help="durée totale ; 0 = jusqu'à Ctrl-C")
    add_detection_arguments(watch)
    watch.set_defaults(handler=run_watch)

    reset_hostnames = subparsers.add_parser(
        "reset-hostnames",
        parents=[common_sub],
        help="vide le cache hostname/MAC sans toucher aux autres historiques",
    )
    reset_hostnames.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        metavar="PATH",
        help=f"fichier d’état à réinitialiser (défaut : {DEFAULT_STATE_FILE})",
    )
    reset_hostnames.set_defaults(handler=run_reset_hostnames)

    subparsers.add_parser("man", help="affiche la page de rappel")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "man":
        print(manual_text())
        return 0

    try:
        suspicious_ports = parse_ports(args.suspicious_ports)
        context = Context(
            Palette(args.color),
            suspicious_ports,
            display=args.display,
            resolve_hostnames=getattr(args, "resolve_hostnames", False),
        )
        if args.command == "watch":
            context.allow_hosts = parse_allow_hosts(args.allow_host)
            context.confirmations = args.confirmations
            context.alert_cooldown = args.alert_cooldown
            try:
                context.state = StateStore(args.state_file)
                stored_hostnames = context.state.data.get("hostnames", {})
                if isinstance(stored_hostnames, dict):
                    context.hostname_cache = {
                        str(address): str(name)
                        for address, name in stored_hostnames.items()
                        if str(address).strip() and str(name).strip()
                    }
                stored_identities = context.state.data.get("identities", {})
                if isinstance(stored_identities, dict):
                    for address, identity in stored_identities.items():
                        if not isinstance(identity, dict):
                            continue
                        address = str(address).strip()
                        hostname = str(identity.get("hostname", "")).strip()
                        mac = normalise_mac(str(identity.get("mac", "")))
                        if address and hostname:
                            context.hostname_cache[address] = hostname
                        if address and mac and mac != "incomplete":
                            context.mac_cache[address] = mac
                context.hostname_resolution_done = bool(context.hostname_cache)
                if context.state.loaded:
                    context.emit("dim", "STATE", f"historique chargé : {args.state_file}")
                    if context.hostname_cache:
                        context.emit("dim", "STATE", f"{len(context.hostname_cache)} nom(s) DNS chargé(s)")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                context.emit("warn", "STATE", f"historique ignoré : {exc}")
                context.state = StateStore("none")
            if args.event_log.lower() not in ("", "none", "-", "off"):
                context.event_log = Path(args.event_log).expanduser()
        return args.handler(context, args)
    except ValueError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
