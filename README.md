# ☠️ REAPER
### Recon, Exploit, Analysis & Post-exploitation Reporting Engine

> Ferramenta de terminal para Kali Linux que guia o utilizador pelos **7 passos de um pentest** — com motor de inteligência, árvore de decisão por vector de ataque, e geração de relatório final em PDF/TXT.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-2023%2B-557C94?style=flat-square&logo=kalilinux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Em_desenvolvimento-yellow?style=flat-square)

---

## 📸 Preview

```
╔══════════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗           ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗          ║
║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝          ║
║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗          ║
║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║          ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝          ║
║          Recon · Exploit · Analysis · Post-exploitation      ║
║                         by Craveiro                          ║
╚══════════════════════════════════════════════════════════════╝
```

---

## ⚡ O que é o REAPER?

O REAPER é uma **framework de pentest em terminal**, inspirada no estilo do Metasploit, que:

- Guia o utilizador pelos **7 passos de um ataque** de forma estruturada
- Tem um **Motor de Inteligência** que analisa os outputs do nmap e sugere vectores de ataque automaticamente
- Possui uma **árvore de decisão** com mais de **25 vectores de ataque** e **150+ técnicas** guiadas
- Permite **executar ferramentas reais** directamente no terminal com parâmetros guiados e dicas contextuais
- **Guarda o progresso** do projecto em JSON e gera **relatório final em PDF ou TXT**
- Nunca fecha o caminho — se uma técnica falhar, voltas atrás e tentas outra

---

## 🗂️ Os 7 Passos

| # | Fase | Ferramentas |
|---|------|-------------|
| 1 | 🔍 Reconhecimento | whois, nslookup, dig, dig axfr, theHarvester, netdiscover, ping sweep, traceroute |
| 2 | 📡 Scanning | nmap (básico, completo, UDP, vuln, evasão firewall), masscan |
| 3 | 🔎 Enumeração | gobuster, feroxbuster, ffuf, dirb, nikto, nikto SSL, wpscan, enum4linux, smbclient, smbmap, snmpwalk, nmap ssh-enum, ftp anónimo |
| 4 | 🐛 Análise de Vulnerabilidades | nmap --script vuln, searchsploit, nmap vulners, nuclei, msfconsole search |
| 5 | 💥 Exploração | hydra (SSH/FTP/HTTP), john, hashcat, msfvenom, reverse shell bash, netcat listener, sqlmap |
| 6 | 🏠 Pós-Exploração | linpeas, sudo -l, SUID/SGID, crontab, capabilities, rede interna, exfiltração SCP |
| 7 | 📄 Relatório | Geração automática PDF / TXT com toda a informação recolhida |

---

## 🧠 Motor de Inteligência

O REAPER inclui um motor de análise que:

1. **Analisa o output do nmap** — detecta automaticamente os serviços activos
2. **Apresenta os vectores de ataque disponíveis** para cada serviço encontrado
3. **Guia passo a passo** com dicas contextuais antes de cada técnica
4. **Regista o resultado** (✔ sucesso / ✘ falhou) e sugere o próximo caminho
5. **Nunca fecha a árvore** — podes sempre voltar e tentar outro vector

### Vectores suportados

| Vector | Técnicas disponíveis |
|--------|----------------------|
| 📁 FTP | Acesso anónimo, brute force, vsftpd 2.3.4 backdoor, download de ficheiros, searchsploit |
| 🔐 SSH | Brute force, enumeração de users, login com credenciais, exploits por versão |
| 🌐 HTTP / Web | nikto, gobuster, feroxbuster, ffuf, SQLMap (injection + dump), LFI, upload de shell PHP, hydra HTTP form, WPScan |
| 📂 SMB / Samba | enum4linux, smbclient, smbmap, EternalBlue (MS17-010), nmap smb-vuln |
| 🗄️ SQL / Base de Dados | MySQL sem password, brute force, LOAD_FILE para leitura de ficheiros |
| 🖥️ Apache / Tomcat | Path Traversal CVE-2021-41773, Struts RCE CVE-2017-5638, Shellshock CVE-2014-6271, Heartbleed CVE-2014-0160, Log4Shell CVE-2021-44228, Tomcat Manager upload WAR shell |
| 🌐 WordPress | WPScan completo, brute force admin, XML-RPC brute force, shell via theme editor, File Manager RCE |
| 🌐 Drupal | Drupalgeddon2 CVE-2018-7600, Drupalgeddon3 CVE-2018-7602, OpenID brute force |
| 🖥️ RDP | BlueKeep CVE-2019-0708, DejaBlue CVE-2019-1181/1182, brute force, login com credenciais |
| 📁 NFS | Listar exports, montar partilha, escalada via UID spoofing |
| 🖥️ Windows / AD | MS08-067, PrintNightmare CVE-2021-34527, WinRM, Pass-the-Hash, Kerberoasting, Secretsdump |
| 📡 LDAP / AD | Enumeração anónima, ldapdomaindump, BloodHound, AS-REP Roasting |
| 📧 SMTP / POP3 / IMAP | Enumeração de utilizadores, Open Relay, brute force POP3/IMAP |
| 🗄️ MongoDB | Acesso sem autenticação, dump de databases, nmap enum |
| 🗄️ Redis | Acesso sem auth, RCE via cron job, RCE via SSH authorized_keys |
| 🗄️ MSSQL | Login SA sem password, RCE via xp_cmdshell, brute force |
| 🗄️ Oracle DB | Enumerar SID, brute force, RCE via ODAT |
| 🔧 Jenkins | Acesso anónimo, RCE via Groovy Console, brute force, CVE-2024-23897 LFI/RCE |
| 🐳 Docker | API sem TLS, escape para root do host, escape via socket local |
| 📡 SNMP | Community string brute force, snmpwalk completo |
| 📟 Telnet | Credenciais padrão, brute force |
| 🖥️ VNC | Acesso sem password, brute force, nmap enum |
| 💣 Buffer Overflow | Fuzzing para crash, pattern create/offset, bad chars, shellcode com msfvenom |
| ⬆️ Privesc Linux | linpeas, sudo/GTFObins, SUID/SGID, cron jobs, capabilities, PATH hijacking, kernel exploits, shadow/passwd |
| 🔓 Cracking de Hashes | John the Ripper, Hashcat GPU, unshadow + john |

---

## 🛠️ Instalação

### Pré-requisitos

- **Kali Linux** (recomendado) ou qualquer distro Linux com Python 3.8+
- As ferramentas de pentest já incluídas no Kali (nmap, hydra, gobuster, etc.)

### Passo a Passo

**1. Clonar o repositório**
```bash
git clone https://github.com/Craveirorj/REAPER.git
cd REAPER
```

**2. Instalar dependências Python**
```bash
pip install rich reportlab --break-system-packages
```

> No Kali Linux 2023+ é necessário o flag `--break-system-packages` por causa do ambiente gerido externamente.

**3. Dar permissão de execução (opcional)**
```bash
chmod +x reaper.py
```

**4. Correr o REAPER**
```bash
python3 reaper.py
```

---

## 🚀 Utilização Rápida

```bash
# Clonar e instalar
git clone https://github.com/Craveirorj/REAPER.git
cd REAPER
pip install rich reportlab --break-system-packages

# Correr
python3 reaper.py
```

### Fluxo básico

```
1. Menu Principal → [1] Novo Projecto
2. Definir nome e IP do alvo
3. Percorrer as fases (1 a 7)
4. Em cada fase → escolher ferramenta → preencher parâmetros → executar
5. Menu Principal → [I] Motor de Inteligência → analisar output do nmap
6. Seguir a árvore de decisão consoante os vectores encontrados
7. Menu Principal → [R] Relatório → gerar PDF ou TXT
```

### Motor de Inteligência — fluxo

```
[I] Motor de Inteligência
  ├── [1] Colar/carregar output do nmap → detecção automática de vectores
  ├── [2] Escolher vector manualmente
  ├── [3] Escalada de Privilégios (após acesso inicial)
  └── [4] Cracking de Hashes

Por cada vector:
  → Lista de técnicas disponíveis com estado (✔ OK / ✘ Fail / — por tentar)
  → Dicas contextuais antes de executar
  → Execução real da ferramenta no terminal
  → Pergunta o resultado e sugere o próximo passo automaticamente
```

---

## 📦 Dependências

| Pacote | Versão | Para quê |
|--------|--------|----------|
| `rich` | ≥ 13.0 | Interface de terminal (cores, tabelas, menus) |
| `reportlab` | ≥ 4.0 | Geração de relatórios em PDF |

As restantes ferramentas (nmap, hydra, gobuster, sqlmap, etc.) já estão incluídas no Kali Linux por defeito.

---

## 📁 Estrutura do Projecto

```
REAPER/
├── reaper.py          # Ficheiro principal — tudo numa única ferramenta
├── README.md          # Documentação
├── .gitignore         # Exclui projectos e relatórios gerados
└── LICENSE            # MIT License

# Gerado automaticamente durante uso (excluído do git):
├── reaper_<nome>_<data>.json        # Dados do projecto guardados
└── reaper_report_<nome>.<pdf/txt>   # Relatório final gerado
```

---

## 💬 Feedback e Contribuições

Este projecto está em constante desenvolvimento. Se testares o REAPER num lab ou CTF, **a tua opinião é bem-vinda!**

- 🐛 Encontraste um bug? Abre uma [Issue](https://github.com/Craveirorj/REAPER/issues)
- 💡 Tens uma ideia para nova funcionalidade? Abre uma [Issue](https://github.com/Craveirorj/REAPER/issues) com a sugestão
- 🔧 Queres contribuir com código? Faz um Fork e abre um Pull Request

Qualquer feedback — grande ou pequeno — ajuda o projecto a crescer.

---

## ⚠️ Aviso Legal / Disclaimer

> **Este projecto foi desenvolvido exclusivamente para fins educativos, em ambiente controlado, como parte de formação em cibersegurança.**
>
> O REAPER deve ser usado **apenas em sistemas para os quais tens autorização explícita** por escrito. A utilização desta ferramenta em sistemas sem autorização é **ilegal** e contrária à ética profissional.
>
> O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

---

## 👤 Autor

**Craveiro**
Formação em Cibersegurança — Pentest, Network Security, CTF

[![LinkedIn](https://img.shields.io/badge/LinkedIn-blue?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/ricardo-craveiro-751512150/)
[![GitHub](https://img.shields.io/badge/GitHub-black?style=flat-square&logo=github)](https://github.com/Craveirorj)

---

## 📝 Licença

Este projecto está licenciado sob a [MIT License](LICENSE).

---

*"Know your enemy and know yourself." — Sun Tzu*
