#!/usr/bin/env python3
"""
RECON SCANNER - Python Module
Fase de Reconhecimento: fingerprint, OSINT, web enum, port scan fallback
Uso: python3 recon_scanner.py --target <IP|HOST> [opções]
"""

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import os
import queue
import random
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

# ──────────────────────────────────────────────────────────────
# Cores ANSI
# ──────────────────────────────────────────────────────────────
class C:
    RED    = '\033[0;31m'
    GREEN  = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN   = '\033[0;36m'
    BLUE   = '\033[0;34m'
    BOLD   = '\033[1m'
    NC     = '\033[0m'

def log(msg):  print(f"{C.GREEN}[+]{C.NC} {msg}")
def info(msg): print(f"{C.BLUE}[*]{C.NC} {msg}")
def warn(msg): print(f"{C.YELLOW}[!]{C.NC} {msg}")
def err(msg):  print(f"{C.RED}[-]{C.NC} {msg}")
def sep():     print(f"{C.CYAN}{'─'*46}{C.NC}")

# ──────────────────────────────────────────────────────────────
# Serviços conhecidos
# ──────────────────────────────────────────────────────────────
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 512: "rexec",
    513: "rlogin", 514: "rsh", 587: "SMTP-sub", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev-HTTP", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "K8s API", 7001: "WebLogic",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 9300: "Elasticsearch-C",
    10250: "K8s Kubelet", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 50000: "SAP",
}

# Probes de banner por serviço
BANNER_PROBES = {
    21:  b"",
    22:  b"",
    25:  b"EHLO recon\r\n",
    80:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110: b"",
    143: b"",
    443: None,  # SSL
    3306: b"",
    6379: b"PING\r\n",
    27017: b"",
}

# ──────────────────────────────────────────────────────────────
# Classe Principal de Reconhecimento
# ──────────────────────────────────────────────────────────────
class ReconScanner:

    def __init__(self, target: str, threads: int = 100,
                 timeout: float = 2.0, stealth: bool = False):
        self.target   = target
        self.threads  = threads
        self.timeout  = timeout
        self.stealth  = stealth
        self.target_ip: Optional[str] = None
        self.open_ports: list[dict]   = []
        self.results: dict            = {
            "target": target, "ip": None,
            "hostname": None, "timestamp": datetime.now().isoformat(),
            "ports": [], "services": {}, "web": {}, "ssl": {}
        }
        self._lock = threading.Lock()

    # ── Resolução ─────────────────────────────────────────────
    def resolve(self) -> Optional[str]:
        try:
            ip = socket.gethostbyname(self.target)
            self.target_ip = ip
            self.results["ip"] = ip
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.results["hostname"] = hostname
            except Exception:
                pass
            log(f"Resolvido: {self.target} → {ip}")
            if self.results["hostname"]:
                log(f"Hostname reverso: {self.results['hostname']}")
            return ip
        except socket.gaierror as e:
            err(f"Não foi possível resolver {self.target}: {e}")
            return None

    # ── Port scan individual ───────────────────────────────────
    def _scan_port(self, port: int) -> Optional[dict]:
        if self.stealth:
            time.sleep(random.uniform(0.01, 0.3))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                service = KNOWN_PORTS.get(port, "unknown")
                banner  = self._grab_banner(sock, port)
                sock.close()
                return {"port": port, "state": "open",
                        "service": service, "banner": banner}
            sock.close()
        except Exception:
            pass
        return None

    # ── Banner grab ────────────────────────────────────────────
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(2)
            probe = BANNER_PROBES.get(port, b"\r\n")
            if probe is None:
                return "[SSL - use ssl_info()]"
            if probe:
                sock.send(probe)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:120].replace("\n", " ").replace("\r", "")
        except Exception:
            return ""

    # ── Port scan completo (multithreaded) ────────────────────
    def scan_ports(self, port_start: int = 1, port_end: int = 1024) -> list:
        info(f"Port scan Python: {self.target_ip} | "
             f"{port_start}-{port_end} | threads={self.threads}")
        sep()

        ports = list(range(port_start, port_end + 1))
        total = len(ports)
        done  = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_port, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                done += 1
                res = fut.result()
                if res:
                    with self._lock:
                        self.open_ports.append(res)
                        self.results["ports"].append(res)
                        banner_str = f" | {res['banner']}" if res['banner'] else ""
                        print(f"{C.GREEN}[OPEN]{C.NC}  "
                              f"{res['port']:5d}/tcp  {res['service']:<15}{banner_str}")
                # Progress
                if done % 500 == 0 or done == total:
                    pct = (done / total) * 100
                    print(f"\r{C.YELLOW}[*]{C.NC} Progress: {done}/{total} "
                          f"({pct:.1f}%)  ", end="", flush=True)

        print()
        sep()
        log(f"Portas abertas: {len(self.open_ports)}")
        return self.open_ports

    # ── SSL/TLS Info ──────────────────────────────────────────
    def get_ssl_info(self, port: int = 443) -> dict:
        ssl_info = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with ctx.wrap_socket(
                socket.create_connection((self.target_ip, port), timeout=5),
                server_hostname=self.target
            ) as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    "version"    : ssock.version(),
                    "cipher"     : ssock.cipher(),
                    "subject"    : dict(x[0] for x in cert.get("subject", [])),
                    "issuer"     : dict(x[0] for x in cert.get("issuer", [])),
                    "not_before" : cert.get("notBefore"),
                    "not_after"  : cert.get("notAfter"),
                    "san"        : [v for _, v in cert.get("subjectAltName", [])],
                }
                log(f"SSL/TLS ({port}): {ssl_info['version']} | {ssl_info['cipher'][0]}")
                if ssl_info["san"]:
                    log(f"SANs: {', '.join(ssl_info['san'][:10])}")
        except Exception as e:
            warn(f"SSL info falhou na porta {port}: {e}")

        self.results["ssl"][port] = ssl_info
        return ssl_info

    # ── HTTP Fingerprint ──────────────────────────────────────
    def http_fingerprint(self, port: int = 80, use_ssl: bool = False) -> dict:
        scheme = "https" if use_ssl else "http"
        url    = f"{scheme}://{self.target}:{port}/"
        fp     = {"url": url}

        paths_to_check = [
            "/", "/robots.txt", "/sitemap.xml", "/.git/HEAD",
            "/admin", "/wp-login.php", "/phpmyadmin",
            "/.env", "/config.php", "/.htaccess",
            "/server-status", "/server-info",
            "/api/", "/api/v1/", "/swagger.json",
            "/actuator/health", "/metrics",
        ]

        headers_interest = [
            "server", "x-powered-by", "x-generator", "x-cms",
            "x-frame-options", "content-security-policy",
            "strict-transport-security", "x-content-type-options",
            "set-cookie", "location", "www-authenticate",
        ]

        try:
            ctx = ssl._create_unverified_context() if use_ssl else None
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (recon-tool)"
            })
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            fp["status_code"] = resp.status
            fp["headers"]     = {}

            for h in headers_interest:
                val = resp.getheader(h)
                if val:
                    fp["headers"][h] = val
                    info(f"  {h}: {val}")

            # Ler primeiros bytes do body
            body = resp.read(2048).decode("utf-8", errors="ignore")
            fp["body_preview"] = body[:500]

            # Detectar tecnologias no body
            techs = self._detect_tech(body, fp.get("headers", {}))
            fp["technologies"] = techs
            if techs:
                log(f"Tecnologias detectadas: {', '.join(techs)}")

        except Exception as e:
            fp["error"] = str(e)

        # Verificar paths sensíveis
        interesting = []
        for path in paths_to_check[1:]:
            try:
                req = urllib.request.Request(
                    f"{scheme}://{self.target}:{port}{path}",
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                r = urllib.request.urlopen(
                    req, timeout=3,
                    context=ssl._create_unverified_context() if use_ssl else None
                )
                if r.status in (200, 301, 302, 403):
                    interesting.append({"path": path, "status": r.status})
                    print(f"  {C.GREEN}[{r.status}]{C.NC} {path}")
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302, 403):
                    interesting.append({"path": path, "status": e.code})
                    print(f"  {C.YELLOW}[{e.code}]{C.NC} {path}")
            except Exception:
                pass

        fp["interesting_paths"] = interesting
        self.results["web"][port] = fp
        return fp

    # ── Detecção de tecnologia ────────────────────────────────
    def _detect_tech(self, body: str, headers: dict) -> list:
        techs = []
        body_lower = body.lower()

        # Por headers
        srv = headers.get("server", "").lower()
        if "apache"     in srv:   techs.append("Apache")
        if "nginx"      in srv:   techs.append("Nginx")
        if "iis"        in srv:   techs.append("IIS")
        if "cloudflare" in srv:   techs.append("Cloudflare")
        if "lighttpd"   in srv:   techs.append("Lighttpd")

        pw = headers.get("x-powered-by", "").lower()
        if "php"        in pw:    techs.append("PHP")
        if "asp.net"    in pw:    techs.append("ASP.NET")
        if "express"    in pw:    techs.append("Node.js/Express")

        # Por body
        signatures = {
            "WordPress"      : ["wp-content", "wp-includes", "wordpress"],
            "Joomla"         : ["joomla", "/components/com_"],
            "Drupal"         : ["drupal", "sites/all/modules"],
            "Laravel"        : ["laravel_session", "x-csrf-token"],
            "React"          : ["react", "__reactfiber", "reactroot"],
            "Angular"        : ["ng-version", "ng-app", "_nghost"],
            "Vue.js"         : ["vue", "__vue", "v-app"],
            "Bootstrap"      : ["bootstrap"],
            "jQuery"         : ["jquery"],
            "Django"         : ["csrfmiddlewaretoken", "django"],
            "Flask"          : ["werkzeug", "flask"],
            "Spring"         : ["spring", "javax.faces"],
            "Cloudflare"     : ["__cfduid", "cf-ray"],
        }
        for tech, sigs in signatures.items():
            if any(s in body_lower for s in sigs):
                techs.append(tech)

        return list(set(techs))

    # ── Ping / ICMP check ─────────────────────────────────────
    def ping_check(self) -> bool:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", self.target_ip],
                capture_output=True, timeout=5
            )
            alive = result.returncode == 0
            status = f"{C.GREEN}ALIVE{C.NC}" if alive else f"{C.RED}NO RESPONSE{C.NC}"
            log(f"Ping: {status}")
            return alive
        except Exception:
            return False

    # ── OS Fingerprint básico ─────────────────────────────────
    def os_fingerprint(self) -> dict:
        fp = {}
        try:
            # TTL heurística
            result = subprocess.run(
                ["ping", "-c", "1", self.target_ip],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "ttl=" in line.lower():
                    ttl = int(line.lower().split("ttl=")[1].split()[0])
                    fp["ttl"] = ttl
                    if ttl >= 128:
                        fp["os_guess"] = "Windows (TTL ~128)"
                    elif ttl >= 64:
                        fp["os_guess"] = "Linux/Unix (TTL ~64)"
                    elif ttl >= 255:
                        fp["os_guess"] = "Cisco/Network Device (TTL ~255)"
                    else:
                        fp["os_guess"] = f"Unknown (TTL={ttl})"
                    log(f"OS heurístico: {fp.get('os_guess', 'N/A')} | TTL={ttl}")
        except Exception:
            pass
        return fp

    # ── Análise de rede (vizinhos, gateway) ──────────────────
    def network_info(self) -> dict:
        info_data = {}
        try:
            # IP info
            is_private = ipaddress.ip_address(self.target_ip).is_private
            info_data["is_private"] = is_private
            log(f"IP privado: {is_private}")

            if is_private:
                # Descoberta ARP local
                try:
                    r = subprocess.run(
                        ["arp", "-n", self.target_ip],
                        capture_output=True, text=True, timeout=5
                    )
                    info_data["arp"] = r.stdout.strip()
                    if r.stdout:
                        info(f"ARP: {r.stdout.strip()[:100]}")
                except Exception:
                    pass
        except ValueError:
            # É um hostname
            pass

        return info_data

    # ── Subdomain/Virtual Host hints ──────────────────────────
    def dns_enum(self) -> dict:
        common_subs = [
            "www", "mail", "ftp", "vpn", "remote", "admin", "portal",
            "dev", "staging", "api", "blog", "app", "test", "secure",
            "mx", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
        ]
        found = {}
        target_domain = self.target

        # Se for IP, pular
        try:
            ipaddress.ip_address(self.target)
            info("Alvo é IP - pulando subdomain enum")
            return {}
        except ValueError:
            pass

        info(f"Testando subdomínios comuns de {target_domain}...")
        for sub in common_subs:
            fqdn = f"{sub}.{target_domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found[fqdn] = ip
                log(f"  Subdomain: {fqdn} → {ip}")
            except Exception:
                pass
            time.sleep(0.05)

        self.results["subdomains"] = found
        return found

    # ── Relatório ─────────────────────────────────────────────
    def save_report(self, output_file: str):
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        log(f"Relatório JSON salvo → {output_file}")

    def print_summary(self):
        sep()
        print(f"{C.BOLD}{C.CYAN}SUMÁRIO - {self.target}{C.NC}")
        sep()
        print(f"  IP       : {self.results.get('ip', 'N/A')}")
        print(f"  Hostname : {self.results.get('hostname', 'N/A')}")
        print(f"  Portas   : {len(self.open_ports)} abertas")
        if self.open_ports:
            ports_str = ", ".join(str(p["port"]) for p in
                                  sorted(self.open_ports, key=lambda x: x["port"]))
            print(f"  Abertas  : {ports_str}")
        sep()

# ──────────────────────────────────────────────────────────────
# Modo Web standalone
# ──────────────────────────────────────────────────────────────
def run_web_mode(scanner: ReconScanner, output: str):
    info("Modo WEB: enumeração HTTP/HTTPS")
    for port, use_ssl in [(80, False), (443, True), (8080, False), (8443, True)]:
        try:
            s = socket.socket()
            s.settimeout(2)
            if s.connect_ex((scanner.target_ip, port)) == 0:
                info(f"Porta {port} aberta — fingerprint...")
                scanner.http_fingerprint(port, use_ssl)
                if use_ssl:
                    scanner.get_ssl_info(port)
            s.close()
        except Exception:
            pass
    scanner.save_report(output)

# ──────────────────────────────────────────────────────────────
# Modo Full
# ──────────────────────────────────────────────────────────────
def run_full_mode(scanner: ReconScanner, output: str,
                  port_start: int, port_end: int, threads: int, timeout: float):
    scanner.ping_check()
    scanner.os_fingerprint()
    scanner.network_info()
    scanner.dns_enum()
    scanner.scan_ports(port_start, port_end)
    # Fingerprint em portas web abertas
    for p_info in scanner.open_ports:
        port = p_info["port"]
        if port in (80, 8080):
            scanner.http_fingerprint(port, False)
        elif port in (443, 8443):
            scanner.http_fingerprint(port, True)
            scanner.get_ssl_info(port)
    scanner.print_summary()
    scanner.save_report(output)

# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Recon Scanner Python - Módulo de reconhecimento"
    )
    parser.add_argument("--target",     required=True, help="IP ou hostname")
    parser.add_argument("--mode",       default="full",
                        choices=["full", "ports", "web", "dns"],
                        help="Modo de operação")
    parser.add_argument("--port-start", type=int, default=1)
    parser.add_argument("--port-end",   type=int, default=1024)
    parser.add_argument("--threads",    type=int, default=100)
    parser.add_argument("--timeout",    type=float, default=2.0)
    parser.add_argument("--stealth",    action="store_true")
    parser.add_argument("--output",     default="recon_python.json")
    args = parser.parse_args()

    print(f"\n{C.CYAN}[Python Recon Module] Alvo: {C.BOLD}{args.target}{C.NC}")
    sep()

    scanner = ReconScanner(
        target  = args.target,
        threads = args.threads,
        timeout = args.timeout,
        stealth = args.stealth,
    )

    if not scanner.resolve():
        sys.exit(1)

    if args.mode == "web":
        run_web_mode(scanner, args.output)
    elif args.mode == "dns":
        scanner.dns_enum()
        scanner.save_report(args.output)
    elif args.mode == "ports":
        scanner.scan_ports(args.port_start, args.port_end)
        scanner.print_summary()
        scanner.save_report(args.output)
    else:  # full
        run_full_mode(scanner, args.output,
                      args.port_start, args.port_end,
                      args.threads, args.timeout)

if __name__ == "__main__":
    main()
