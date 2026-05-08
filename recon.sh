#!/usr/bin/env bash
# ============================================================
#  RECON FRAMEWORK  -  Fase de Reconhecimento Completa
#  Uso: ./recon.sh <IP | HOST> [opções]
#  Autor: recon-toolkit | Shell + Python + C++ integrado
# ============================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

BANNER="
${RED}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
${YELLOW}  [ Reconnaissance & Scanning Framework ]
${GREEN}  Shell + Python + C++ | Apenas IP/Host necessário${NC}
"

# ──────────────────────────────────────────────────────────────
# Configuração
# ──────────────────────────────────────────────────────────────
TARGET=""
OUTPUT_DIR="recon_output"
THREADS=50
TIMEOUT=3
FULL_SCAN=false
STEALTH=false
SKIP_COMPILE=false

usage() {
    echo -e "${CYAN}Uso:${NC} $0 <IP|HOST> [opções]\n"
    echo -e "  ${GREEN}-o DIR${NC}    Diretório de saída (padrão: recon_output)"
    echo -e "  ${GREEN}-t N${NC}      Threads para port scanner C++ (padrão: 50)"
    echo -e "  ${GREEN}-T N${NC}      Timeout em segundos (padrão: 3)"
    echo -e "  ${GREEN}-f${NC}        Full scan (todas as 65535 portas)"
    echo -e "  ${GREEN}-s${NC}        Modo furtivo (delays aleatórios)"
    echo -e "  ${GREEN}-S${NC}        Pular compilação do C++ (usa binário existente)"
    echo -e "  ${GREEN}-h${NC}        Esta ajuda\n"
    echo -e "  ${YELLOW}Exemplos:${NC}"
    echo -e "    $0 192.168.1.1"
    echo -e "    $0 example.com -f -t 100"
    echo -e "    $0 10.0.0.1 -s -o /tmp/scan\n"
    exit 0
}

log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${BLUE}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────────${NC}"; }

# ──────────────────────────────────────────────────────────────
# Parse argumentos
# ──────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && { echo -e "$BANNER"; usage; }
TARGET="$1"; shift

while getopts "o:t:T:fsSh" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        T) TIMEOUT="$OPTARG" ;;
        f) FULL_SCAN=true ;;
        s) STEALTH=true ;;
        S) SKIP_COMPILE=true ;;
        h) echo -e "$BANNER"; usage ;;
        *) err "Opção inválida: -$OPTARG"; usage ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# Setup diretórios
# ──────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_DIR="${OUTPUT_DIR}/${TARGET}_${TIMESTAMP}"
mkdir -p "$SCAN_DIR"/{ports,services,dns,web,vuln,osint}

LOG_FILE="$SCAN_DIR/recon_full.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "$BANNER"
sep
log "Alvo        : ${BOLD}$TARGET${NC}"
log "Diretório   : $SCAN_DIR"
log "Threads     : $THREADS"
log "Timeout     : ${TIMEOUT}s"
log "Full scan   : $FULL_SCAN"
log "Stealth     : $STEALTH"
log "Início      : $(date)"
sep

# ──────────────────────────────────────────────────────────────
# Verificação de dependências
# ──────────────────────────────────────────────────────────────
check_deps() {
    info "Verificando dependências..."
    local MISSING=()
    local DEPS=(python3 nmap dig whois curl wget host ping)

    for dep in "${DEPS[@]}"; do
        command -v "$dep" &>/dev/null || MISSING+=("$dep")
    done

    if [[ ${#MISSING[@]} -gt 0 ]]; then
        warn "Dependências opcionais ausentes: ${MISSING[*]}"
        warn "Instale com: sudo apt install ${MISSING[*]}"
    fi

    # Verificar compilador C++
    if ! command -v g++ &>/dev/null; then
        warn "g++ não encontrado - port scanner C++ desativado"
        SKIP_COMPILE=true
    fi
    log "Verificação concluída"
}

# ──────────────────────────────────────────────────────────────
# Compilar port scanner C++
# ──────────────────────────────────────────────────────────────
compile_cpp_scanner() {
    if [[ "$SKIP_COMPILE" == true ]]; then
        info "Compilação C++ ignorada"
        return
    fi

    info "Compilando port scanner C++..."

    # Gerar o código C++ inline
    cat > /tmp/port_scanner.cpp << 'CPPEOF'
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

// ─── Globals ───────────────────────────────────────────────
std::mutex mtx;
std::queue<int> port_queue;
std::vector<int> open_ports;
std::atomic<int> scanned{0};
std::atomic<int> total_ports{0};

struct Config {
    std::string target;
    std::string target_ip;
    int threads    = 50;
    int timeout    = 3;
    int port_start = 1;
    int port_end   = 1024;
    std::string output_file;
};

// ─── Resolve hostname → IP ─────────────────────────────────
std::string resolve_host(const std::string& host) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return "";
    char ip[INET_ADDRSTRLEN];
    auto* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);
    return std::string(ip);
}

// ─── Grab banner de serviço ────────────────────────────────
std::string grab_banner(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    fcntl(sock, F_SETFL, O_NONBLOCK);
    connect(sock, (struct sockaddr*)&sa, sizeof(sa));

    fd_set wset;
    FD_ZERO(&wset); FD_SET(sock, &wset);
    struct timeval tv{2, 0};
    if (select(sock+1, nullptr, &wset, nullptr, &tv) <= 0) {
        close(sock); return "";
    }

    // Enviar probe HTTP simples
    const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
    send(sock, probe, strlen(probe), 0);

    fd_set rset;
    FD_ZERO(&rset); FD_SET(sock, &rset);
    struct timeval tv2{2, 0};
    char buf[512]{};
    if (select(sock+1, &rset, nullptr, nullptr, &tv2) > 0)
        recv(sock, buf, sizeof(buf)-1, 0);

    close(sock);
    std::string banner(buf);
    // Pegar só primeira linha
    auto nl = banner.find('\n');
    if (nl != std::string::npos) banner = banner.substr(0, nl);
    // Remover chars de controle
    banner.erase(std::remove_if(banner.begin(), banner.end(),
        [](char c){ return c < 32 && c != '\t'; }), banner.end());
    return banner.substr(0, 80);
}

// ─── Nome de serviço por porta ─────────────────────────────
std::string service_name(int port) {
    struct servent* sv = getservbyport(htons(port), "tcp");
    if (sv) return std::string(sv->s_name);
    // Fallback manual para portas comuns
    switch(port) {
        case 21:   return "ftp";
        case 22:   return "ssh";
        case 23:   return "telnet";
        case 25:   return "smtp";
        case 53:   return "dns";
        case 80:   return "http";
        case 110:  return "pop3";
        case 143:  return "imap";
        case 443:  return "https";
        case 445:  return "smb";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 6379: return "redis";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        case 27017:return "mongodb";
        default:   return "unknown";
    }
}

// ─── Worker thread ─────────────────────────────────────────
void scan_worker(const Config& cfg) {
    while (true) {
        int port;
        {
            std::lock_guard<std::mutex> lk(mtx);
            if (port_queue.empty()) return;
            port = port_queue.front();
            port_queue.pop();
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { scanned++; continue; }

        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(port);
        inet_pton(AF_INET, cfg.target_ip.c_str(), &sa.sin_addr);

        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, (struct sockaddr*)&sa, sizeof(sa));

        fd_set fds;
        FD_ZERO(&fds); FD_SET(sock, &fds);
        struct timeval tv{cfg.timeout, 0};

        bool is_open = (select(sock+1, nullptr, &fds, nullptr, &tv) > 0);
        close(sock);
        scanned++;

        if (is_open) {
            std::string svc    = service_name(port);
            std::string banner = grab_banner(cfg.target_ip, port);
            {
                std::lock_guard<std::mutex> lk(mtx);
                open_ports.push_back(port);
                std::cout << "\033[32m[OPEN]\033[0m  "
                          << port << "/tcp\t" << svc;
                if (!banner.empty()) std::cout << "\t| " << banner;
                std::cout << "\n";
            }
        }
    }
}

// ─── Main ──────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    Config cfg;
    if (argc < 2) {
        std::cerr << "Uso: " << argv[0]
                  << " <IP|HOST> [start_port] [end_port] [threads] [timeout] [output]\n";
        return 1;
    }

    cfg.target = argv[1];
    if (argc > 2) cfg.port_start = std::stoi(argv[2]);
    if (argc > 3) cfg.port_end   = std::stoi(argv[3]);
    if (argc > 4) cfg.threads    = std::stoi(argv[4]);
    if (argc > 5) cfg.timeout    = std::stoi(argv[5]);
    if (argc > 6) cfg.output_file = argv[6];

    // Resolver hostname
    cfg.target_ip = resolve_host(cfg.target);
    if (cfg.target_ip.empty()) {
        std::cerr << "[-] Não foi possível resolver: " << cfg.target << "\n";
        return 1;
    }

    std::cout << "\033[36m[C++ Port Scanner]\033[0m Alvo: "
              << cfg.target << " (" << cfg.target_ip << ")\n";
    std::cout << "Portas: " << cfg.port_start << "-" << cfg.port_end
              << " | Threads: " << cfg.threads
              << " | Timeout: " << cfg.timeout << "s\n";
    std::cout << "\033[33m─────────────────────────────────────────\033[0m\n";

    // Preencher fila de portas
    for (int p = cfg.port_start; p <= cfg.port_end; p++)
        port_queue.push(p);
    total_ports = cfg.port_end - cfg.port_start + 1;

    auto t_start = std::chrono::steady_clock::now();

    // Criar threads
    int n_threads = std::min(cfg.threads, (int)total_ports.load());
    std::vector<std::thread> workers;
    workers.reserve(n_threads);
    for (int i = 0; i < n_threads; i++)
        workers.emplace_back(scan_worker, std::ref(cfg));
    for (auto& t : workers) t.join();

    auto t_end  = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t_end - t_start).count();

    std::sort(open_ports.begin(), open_ports.end());

    std::cout << "\033[33m─────────────────────────────────────────\033[0m\n";
    std::cout << "\033[32m[+]\033[0m Portas abertas : " << open_ports.size() << "\n";
    std::cout << "\033[32m[+]\033[0m Tempo total    : " << secs << "s\n";

    // Salvar resultado
    if (!cfg.output_file.empty()) {
        std::ofstream f(cfg.output_file);
        f << "# C++ Port Scanner Result\n";
        f << "# Target: " << cfg.target << " (" << cfg.target_ip << ")\n";
        f << "# Range: " << cfg.port_start << "-" << cfg.port_end << "\n\n";
        for (int p : open_ports)
            f << p << "/tcp\t" << service_name(p) << "\n";
    }

    return 0;
}
CPPEOF

    if g++ -O2 -std=c++17 -pthread /tmp/port_scanner.cpp -o /tmp/port_scanner 2>&1; then
        log "Port scanner C++ compilado com sucesso → /tmp/port_scanner"
    else
        warn "Falha ao compilar C++ - usando fallback Python para port scan"
        SKIP_COMPILE=true
    fi
}

# ──────────────────────────────────────────────────────────────
# FASE 1: Reconhecimento Passivo (OSINT)
# ──────────────────────────────────────────────────────────────
phase_passive_recon() {
    sep
    echo -e "${BOLD}${CYAN}[FASE 1] RECONHECIMENTO PASSIVO${NC}"
    sep
    local OUT="$SCAN_DIR/osint"

    # Whois
    if command -v whois &>/dev/null; then
        info "WHOIS lookup..."
        whois "$TARGET" > "$OUT/whois.txt" 2>/dev/null
        grep -E "(Registrant|Admin|Tech|Name Server|Created|Expires|Updated|Org|Country)" \
            "$OUT/whois.txt" | head -30
        log "WHOIS salvo → $OUT/whois.txt"
    fi

    # DNS - Resolução básica
    if command -v host &>/dev/null; then
        info "Resolução DNS..."
        host "$TARGET" 2>/dev/null | tee "$OUT/host_lookup.txt"
    fi

    # Dig - registros completos
    if command -v dig &>/dev/null; then
        info "Registros DNS completos..."
        {
            echo "=== A Records ==="
            dig +short A "$TARGET" 2>/dev/null
            echo "=== AAAA Records ==="
            dig +short AAAA "$TARGET" 2>/dev/null
            echo "=== MX Records ==="
            dig +short MX "$TARGET" 2>/dev/null
            echo "=== NS Records ==="
            dig +short NS "$TARGET" 2>/dev/null
            echo "=== TXT Records ==="
            dig +short TXT "$TARGET" 2>/dev/null
            echo "=== SOA Record ==="
            dig +short SOA "$TARGET" 2>/dev/null
            echo "=== CNAME ==="
            dig +short CNAME "$TARGET" 2>/dev/null
            echo "=== ANY (full) ==="
            dig ANY "$TARGET" 2>/dev/null
        } | tee "$OUT/dns_records.txt"
        log "Registros DNS salvos → $OUT/dns_records.txt"
    fi

    # Reverso PTR
    if command -v dig &>/dev/null; then
        info "PTR Reverso..."
        dig -x "$TARGET" +short 2>/dev/null | tee "$OUT/ptr_reverse.txt" || true
    fi
}

# ──────────────────────────────────────────────────────────────
# FASE 2: Port Scanning (C++ ou fallback Python)
# ──────────────────────────────────────────────────────────────
phase_port_scan() {
    sep
    echo -e "${BOLD}${CYAN}[FASE 2] PORT SCANNING${NC}"
    sep

    local PORT_START=1
    local PORT_END=1024
    [[ "$FULL_SCAN" == true ]] && PORT_END=65535

    if [[ "$SKIP_COMPILE" == false && -f /tmp/port_scanner ]]; then
        log "Usando port scanner C++ (rápido, multithreaded)..."
        /tmp/port_scanner "$TARGET" "$PORT_START" "$PORT_END" \
            "$THREADS" "$TIMEOUT" "$SCAN_DIR/ports/cpp_scan.txt"
    else
        log "Usando port scanner Python (fallback)..."
        python3 recon_scanner.py \
            --target "$TARGET" \
            --port-start "$PORT_START" \
            --port-end "$PORT_END" \
            --threads "$THREADS" \
            --timeout "$TIMEOUT" \
            --output "$SCAN_DIR/ports/python_scan.txt" 2>/dev/null \
            || warn "recon_scanner.py não encontrado no diretório atual"
    fi
}

# ──────────────────────────────────────────────────────────────
# FASE 3: Nmap Deep Scan
# ──────────────────────────────────────────────────────────────
phase_nmap() {
    sep
    echo -e "${BOLD}${CYAN}[FASE 3] NMAP ADVANCED SCAN${NC}"
    sep

    if ! command -v nmap &>/dev/null; then
        warn "nmap não instalado. Pulando fase 3."
        return
    fi

    local NMAP_OUT="$SCAN_DIR/ports"

    # Descoberta de host
    info "Ping/host discovery..."
    nmap -sn "$TARGET" -oN "$NMAP_OUT/host_discovery.txt" 2>/dev/null

    # SYN scan + detecção de versão
    info "SYN scan + detecção de versão e OS..."
    local PORTS="1-1024"
    [[ "$FULL_SCAN" == true ]] && PORTS="1-65535"

    local STEALTH_OPT=""
    [[ "$STEALTH" == true ]] && STEALTH_OPT="-T1 --randomize-hosts"
    [[ "$STEALTH" == false ]] && STEALTH_OPT="-T4"

    nmap $STEALTH_OPT -sS -sV -O \
        --version-intensity 7 \
        -p "$PORTS" \
        --script=banner,default \
        -oA "$NMAP_OUT/nmap_full" \
        "$TARGET" 2>/dev/null \
        | tee "$NMAP_OUT/nmap_output.txt"

    log "Resultados nmap salvos → $NMAP_OUT/nmap_full.*"

    # Vuln scan básico
    info "Nmap vuln scripts..."
    nmap -sV --script=vuln \
        -p "$(awk '/open/{print $1}' "$NMAP_OUT/nmap_output.txt" 2>/dev/null | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')" \
        "$TARGET" \
        -oN "$SCAN_DIR/vuln/nmap_vuln.txt" 2>/dev/null || true

    log "Vuln scan salvo → $SCAN_DIR/vuln/nmap_vuln.txt"
}

# ──────────────────────────────────────────────────────────────
# FASE 4: Enumeração de Serviços Web
# ──────────────────────────────────────────────────────────────
phase_web_enum() {
    sep
    echo -e "${BOLD}${CYAN}[FASE 4] ENUMERAÇÃO WEB${NC}"
    sep

    local WEB_OUT="$SCAN_DIR/web"

    # Verificar se porta 80/443 está aberta
    for port in 80 443 8080 8443; do
        if timeout 3 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null; then
            local PROTO="http"
            [[ $port == 443 || $port == 8443 ]] && PROTO="https"

            info "Porta $port aberta - enumerando $PROTO..."

            # Headers HTTP
            curl -skI --max-time 10 "$PROTO://$TARGET:$port" \
                > "$WEB_OUT/headers_${port}.txt" 2>/dev/null
            log "Headers HTTP ($port) → $WEB_OUT/headers_${port}.txt"

            # Robots.txt
            curl -sk --max-time 10 "$PROTO://$TARGET:$port/robots.txt" \
                > "$WEB_OUT/robots_${port}.txt" 2>/dev/null

            # Sitemap
            curl -sk --max-time 10 "$PROTO://$TARGET:$port/sitemap.xml" \
                > "$WEB_OUT/sitemap_${port}.txt" 2>/dev/null

            # Info do servidor
            grep -iE "(server|x-powered-by|x-generator|x-cms|set-cookie|location)" \
                "$WEB_OUT/headers_${port}.txt" 2>/dev/null
        fi
    done

    # Chamar Python para análise web avançada
    python3 recon_scanner.py \
        --target "$TARGET" \
        --mode web \
        --output "$WEB_OUT/web_analysis.txt" 2>/dev/null || true
}

# ──────────────────────────────────────────────────────────────
# FASE 5: Análise Python (OSINT avançado + fingerprint)
# ──────────────────────────────────────────────────────────────
phase_python_analysis() {
    sep
    echo -e "${BOLD}${CYAN}[FASE 5] ANÁLISE PYTHON (FINGERPRINT & OSINT)${NC}"
    sep

    if ! python3 -c "import socket,threading,http.client" 2>/dev/null; then
        warn "Python3 não disponível para análise avançada"
        return
    fi

    python3 recon_scanner.py \
        --target "$TARGET" \
        --mode full \
        --output "$SCAN_DIR/services/python_analysis.txt" 2>/dev/null \
        || info "Execute: python3 recon_scanner.py --target $TARGET --mode full"
}

# ──────────────────────────────────────────────────────────────
# FASE 6: Relatório Final
# ──────────────────────────────────────────────────────────────
generate_report() {
    sep
    echo -e "${BOLD}${CYAN}[FASE 6] GERANDO RELATÓRIO FINAL${NC}"
    sep

    local REPORT="$SCAN_DIR/REPORT_${TARGET}.txt"
    {
        echo "════════════════════════════════════════════════════"
        echo "  RECON REPORT - $TARGET"
        echo "  Data: $(date)"
        echo "════════════════════════════════════════════════════"
        echo ""

        echo "[INFORMAÇÕES DO ALVO]"
        echo "Target   : $TARGET"
        echo "IP       : $(dig +short A "$TARGET" 2>/dev/null | head -1)"
        echo "Hostname : $(dig -x "$TARGET" +short 2>/dev/null | head -1)"
        echo ""

        echo "[PORTAS ABERTAS - C++]"
        [[ -f "$SCAN_DIR/ports/cpp_scan.txt" ]] \
            && cat "$SCAN_DIR/ports/cpp_scan.txt" \
            || echo "N/A"
        echo ""

        echo "[PORTAS ABERTAS - NMAP]"
        [[ -f "$SCAN_DIR/ports/nmap_output.txt" ]] \
            && grep "open" "$SCAN_DIR/ports/nmap_output.txt" | head -50 \
            || echo "N/A"
        echo ""

        echo "[HEADERS HTTP]"
        for f in "$SCAN_DIR/web/headers_"*.txt; do
            [[ -f "$f" ]] && { echo "--- $f ---"; cat "$f"; echo; }
        done

        echo "[WHOIS - RESUMO]"
        [[ -f "$SCAN_DIR/osint/whois.txt" ]] \
            && grep -E "(Registrant|Org|Country|Created|Expires)" \
               "$SCAN_DIR/osint/whois.txt" | head -20 \
            || echo "N/A"
        echo ""

        echo "[DNS RECORDS]"
        [[ -f "$SCAN_DIR/osint/dns_records.txt" ]] \
            && cat "$SCAN_DIR/osint/dns_records.txt" \
            || echo "N/A"

        echo ""
        echo "════════════════════════════════════════════════════"
        echo "  Arquivos gerados em: $SCAN_DIR"
        echo "════════════════════════════════════════════════════"
    } > "$REPORT"

    log "Relatório salvo → $REPORT"
    sep
    echo -e "${GREEN}${BOLD}SCAN COMPLETO!${NC}"
    echo -e "${CYAN}Arquivos em:${NC} $SCAN_DIR"
    echo -e "${CYAN}Relatório  :${NC} $REPORT"
    sep
}

# ──────────────────────────────────────────────────────────────
# MAIN - Executar todas as fases
# ──────────────────────────────────────────────────────────────
main() {
    check_deps
    compile_cpp_scanner
    phase_passive_recon
    phase_port_scan
    phase_nmap
    phase_web_enum
    phase_python_analysis
    generate_report
}

main
