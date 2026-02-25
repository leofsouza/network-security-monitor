# 🔍 Network Security Monitor

> Ferramenta de monitorização de rede em tempo real que deteta novos dispositivos, portas perigosas abertas e alterações na topologia da rede local — com alertas automáticos por e-mail.

---

## 📋 Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Como Funciona](#como-funciona)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Como Executar](#como-executar)
- [Automatização](#automatização)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Exemplo de Relatório](#exemplo-de-relatório)
- [Limitações Conhecidas](#limitações-conhecidas)
- [Melhorias Futuras](#melhorias-futuras)

---

## 📖 Sobre o Projeto

Este projeto nasceu da necessidade de ter **visibilidade total sobre os dispositivos conectados na rede doméstica/corporativa**. A maioria das pessoas não sabe quantos dispositivos estão ligados à sua rede nem quais portas estão expostas — o que representa um risco de segurança real.

O **Network Security Monitor** resolve isso com uma varredura diária automatizada que:
- Identifica todos os dispositivos ativos na rede
- Compara com o inventário do dia anterior
- Gera alertas imediatos quando algo novo ou suspeito é detetado
- Envia relatórios detalhados por e-mail em formato HTML

---

## ✨ Funcionalidades

### 🔎 Varredura de Rede
- **Ping Sweep** — deteta todos os hosts ativos na sub-rede sem gerar muito tráfego
- **Port Scan** — verifica portas perigosas conhecidas em cada dispositivo ativo
- Suporte a **múltiplas sub-redes** simultâneas

### 🚨 Deteção de Ameaças
- Novos dispositivos não catalogados na rede
- Portas perigosas abertas repentinamente (RDP, SSH, Telnet, SMB, VNC, etc.)
- Dispositivos que desapareceram da rede
- Lista de dispositivos aprovados para filtrar falsos positivos

### 📧 Alertas e Relatórios
- Relatório diário por e-mail em **HTML formatado**
- Alerta imediato com nível de criticidade (🟢 Normal / 🚨 Alerta)
- Tabela completa com IP, Hostname, Fabricante, MAC Address, SSID Wi-Fi e Portas Abertas
- Registo completo em ficheiro `.log`

### 🏭 Identificação de Dispositivos
- Resolução de **hostname** via DNS reverso
- Identificação do **fabricante** pelo prefixo do MAC Address (OUI)
- Deteção automática do **nome da rede Wi-Fi (SSID)**
- Distinção entre dispositivos cabeados e wireless

---

## ⚙️ Como Funciona

```
┌─────────────────────────────────────────────────────────┐
│                    FLUXO DE EXECUÇÃO                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Carrega scan anterior (scan_ontem.json)             │
│                    ↓                                    │
│  2. Fase 1 — Ping Sweep na sub-rede                     │
│     └─ Identifica todos os hosts ativos                 │
│                    ↓                                    │
│  3. Fase 2 — Port Scan em cada host ativo               │
│     └─ Verifica 12 portas perigosas conhecidas          │
│                    ↓                                    │
│  4. Enriquecimento de dados                             │
│     ├─ Resolução de hostname (DNS reverso)              │
│     ├─ Identificação do fabricante (MAC OUI)            │
│     └─ Deteção do SSID Wi-Fi                            │
│                    ↓                                    │
│  5. Comparação com scan anterior                        │
│     ├─ Novos dispositivos?                              │
│     ├─ Novas portas abertas?                            │
│     └─ Dispositivos desaparecidos?                      │
│                    ↓                                    │
│  6. Guarda resultados (scan_hoje.json)                  │
│                    ↓                                    │
│  7. Envia relatório por e-mail (HTML)                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Portas Monitorizadas

| Porta | Serviço | Risco |
|-------|---------|-------|
| 21 | FTP | Alto — transferência de ficheiros sem encriptação |
| 22 | SSH | Médio — acesso remoto, pode ser alvo de brute force |
| 23 | Telnet | Crítico — protocolo completamente inseguro |
| 25 | SMTP | Médio — pode indicar servidor de e-mail não autorizado |
| 80 | HTTP | Baixo — servidor web sem encriptação |
| 443 | HTTPS | Baixo — servidor web com encriptação |
| 445 | SMB | Alto — partilha de ficheiros Windows, alvo de ransomware |
| 1433 | MSSQL | Alto — base de dados exposta |
| 3306 | MySQL | Alto — base de dados exposta |
| 3389 | RDP | Crítico — acesso remoto ao ambiente de trabalho Windows |
| 5900 | VNC | Alto — acesso remoto ao ecrã |
| 8080 | HTTP-Alt | Médio — servidor web alternativo |

---

## 🛠️ Tecnologias Utilizadas

| Tecnologia | Versão | Utilização |
|-----------|--------|------------|
| Python | 3.11+ | Linguagem principal |
| python-nmap | 0.7.1+ | Interface com o motor de scan Nmap |
| Nmap | 7.9+ | Motor de varredura de rede |
| smtplib | built-in | Envio de e-mails via SMTP |
| socket | built-in | Resolução de hostnames |
| json | built-in | Persistência dos resultados |
| logging | built-in | Registo de eventos |
| subprocess | built-in | Deteção do SSID Wi-Fi via netsh |

---

## 📦 Pré-requisitos

- **Windows 10/11** (também compatível com Linux/macOS com ajustes menores)
- **Python 3.11+** — [download aqui](https://python.org/downloads)
- **Nmap 7.9+** — [download aqui](https://nmap.org/download.html)
- Conta **Gmail** com App Password configurada
- Execução com **privilégios de administrador** (necessário para obter MACs via nmap)

---

## 🚀 Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/teu-utilizador/network-security-monitor.git
cd network-security-monitor
```

### 2. Instalar o Nmap

**Via winget (recomendado):**
```cmd
winget install Insecure.Nmap
```

**Via instalador:** acede a [nmap.org/download.html](https://nmap.org/download.html) e executa o instalador Windows.

Após a instalação, adiciona ao PATH:
```cmd
setx PATH "%PATH%;C:\Program Files (x86)\Nmap" /M
```

Verifica a instalação:
```cmd
nmap --version
```

### 3. Instalar dependências Python

```cmd
pip install python-nmap
```

---

## ⚙️ Configuração

Abre o ficheiro `network_monitor.py` e edita a secção de configurações no topo:

```python
# ── Sub-redes a monitorizar ──────────────────────────────
# Corre 'ipconfig' no CMD para descobrir a tua sub-rede
SUBNETS = [
    "192.168.7.0/24",   # Rede Wi-Fi principal
    # "192.168.1.0/24", # Adiciona mais sub-redes se necessário
]

# ── Dispositivos aprovados (não geram alertas) ───────────
DISPOSITIVOS_APROVADOS = {
    "192.168.7.1": "Router Principal",
    "192.168.7.5": "Smart TV",
    "192.168.7.8": "Meu PC",
    # Adiciona todos os teus dispositivos aqui
}

# ── Configurações de e-mail ──────────────────────────────
EMAIL_REMETENTE    = "teu-email@gmail.com"
EMAIL_SENHA        = "xxxx xxxx xxxx xxxx"  # App Password Gmail
EMAIL_DESTINATARIO = "destino@gmail.com"
```

### Configurar App Password no Gmail

1. Ativa a verificação em dois passos em [myaccount.google.com/security](https://myaccount.google.com/security)
2. Acede a [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Cria uma nova App Password com o nome `network-monitor`
4. Copia os 16 caracteres gerados e cola no campo `EMAIL_SENHA` **sem espaços**

### Descobrir a tua sub-rede

```cmd
ipconfig
```

Procura pelo campo **"Endereço IPv4"** — por exemplo `192.168.7.8`. A tua sub-rede é `192.168.7.0/24`.

---

## ▶️ Como Executar

> ⚠️ **Importante:** executa sempre o CMD como **Administrador** para que o nmap consiga obter os MAC addresses.

```cmd
python "C:\caminho\para\network_monitor.py"
```

Na **primeira execução** não haverá alertas pois não existe scan anterior para comparar. A partir da **segunda execução**, qualquer novo dispositivo ou porta aberta irá gerar um alerta.

**Output esperado no terminal:**
```
============================================================
 Monitor de Rede — Início da Varredura
============================================================
2026-02-24 18:00:01 [INFO] Scan anterior: 8 dispositivo(s) registado(s).
2026-02-24 18:00:01 [INFO] A varrer 192.168.7.0/24 (Wi-Fi: MinhaRede-5GHz)...
2026-02-24 18:00:01 [INFO]   Fase 1: Ping sweep...
2026-02-24 18:00:15 [INFO]   6 host(s) ativo(s) encontrado(s).
2026-02-24 18:00:15 [INFO]   Fase 2: Port scan nas portas 21,22,23...
2026-02-24 18:02:30 [INFO]   192.168.7.1 (router) | Huawei | Portas: 22/SSH, 80/HTTP
2026-02-24 18:02:30 [INFO] ✅ Nenhuma alteração detetada.
2026-02-24 18:02:31 [INFO] [✓] Relatório enviado para seguranca@empresa.com
============================================================
```

---

## 🤖 Automatização

### Windows — Agendador de Tarefas

Para executar automaticamente todos os dias:

1. Abre o **Agendador de Tarefas** (Task Scheduler)
2. Clica em **"Criar Tarefa"** (não "Básica")
3. Configura:
   - **Geral:** marca *"Executar com privilégios mais elevados"*
   - **Disparadores:** Diariamente → define a hora desejada (ex: 08:00)
   - **Ações:** Iniciar programa
     - Programa: `python`
     - Argumentos: `"C:\caminho\para\network_monitor.py"`
4. Clica em OK

### Windows — Script .bat com reinício automático

Cria um ficheiro `iniciar.bat`:
```bat
@echo off
:loop
python "C:\caminho\para\network_monitor.py"
timeout /t 86400
goto loop
```

Coloca um atalho para o `.bat` na pasta de arranque automático:
```
Win + R → shell:startup
```

---

## 📁 Estrutura do Projeto

```
network-security-monitor/
│
├── network_monitor.py      # Script principal
├── scan_hoje.json          # Resultados do scan mais recente (gerado automaticamente)
├── scan_ontem.json         # Resultados do scan anterior (gerado automaticamente)
├── network_monitor.log     # Registo completo de todos os scans (gerado automaticamente)
└── README.md               # Este ficheiro
```

---

## 📧 Exemplo de Relatório

O script envia um e-mail HTML com o seguinte aspeto:

**Quando tudo está normal:**
```
✅ Relatório diário — Rede normal
Data/Hora: 2026-02-24 08:00 | Sub-redes: 192.168.7.0/24 | Dispositivos ativos: 6

✅ Nenhuma alteração detetada desde o último scan.

┌─────────────┬──────────────┬────────────────────┬───────────────────┬──────────────┬───────────────┐
│ IP          │ Hostname     │ Fabricante         │ MAC               │ Wi-Fi (SSID) │ Portas Abertas│
├─────────────┼──────────────┼────────────────────┼───────────────────┼──────────────┼───────────────┤
│ 192.168.7.1 │ router       │ Huawei             │ A8:6E:84:CC:2D:72 │ MinhaRede    │ 22/SSH,80/HTTP│
│ 192.168.7.8 │ DESKTOP-XXX  │ Realtek            │ 90:91:64:11:25:62 │ MinhaRede    │ 445/SMB       │
└─────────────┴──────────────┴────────────────────┴───────────────────┴──────────────┴───────────────┘
```

**Quando um novo dispositivo é detetado:**
```
🚨 ALERTA — Novos dispositivos/portas detetados

🆕 Novos Dispositivos Detetados
  • 192.168.7.15 — desconhecido | Samsung | MAC: 40:4E:36:XX:XX:XX | Wi-Fi: MinhaRede

⚠️ Novas Portas Perigosas Abertas
  • 192.168.7.10 (desktop-trabalho) — portas: 3389/RDP
```

---

## ⚠️ Limitações Conhecidas

**MAC Address no Windows** — o nmap precisa de ser executado com privilégios de Administrador para obter o MAC de dispositivos remotos. Sem isso, o campo aparece como "desconhecido".

**Banda Wi-Fi (2.4GHz vs 5GHz)** — o nmap não consegue determinar em que banda cada dispositivo está ligado. Essa informação só está disponível na interface de administração do router. Solução: identificar manualmente e anotar no campo `DISPOSITIVOS_APROVADOS`.

**Rede do ISP** — se adicionares a sub-rede do modem ISP (ex: `192.168.0.0/24`), podem aparecer dispositivos pertencentes à infraestrutura do operador, especialmente em redes de cabo coaxial onde vários clientes partilham o mesmo nó. Recomenda-se monitorizar apenas a rede interna.

**IPs dinâmicos (DHCP)** — dispositivos com IP atribuído dinamicamente podem aparecer como "novos" se o router lhes atribuir um IP diferente. Para evitar falsos positivos, configura reservas de DHCP no router para atribuir sempre o mesmo IP a cada dispositivo.

---

## 🔮 Melhorias Futuras

- [ ] Interface web local para visualizar o histórico de scans
- [ ] Integração com a API do VirusTotal para verificar reputação de IPs
- [ ] Geolocalização do IP de origem para dispositivos externos
- [ ] Notificações via Telegram ou Discord
- [ ] Dashboard com gráfico histórico de dispositivos ativos
- [ ] Verificação de reputação de IPs via AbuseIPDB
- [ ] Exportação de relatórios em PDF
- [ ] Suporte a múltiplas interfaces de rede simultâneas

---

## 📄 Licença

Este projeto está licenciado sob a licença MIT — consulta o ficheiro [LICENSE](LICENSE) para mais detalhes.

---

## 👨‍💻 Autor

Desenvolvido por **Leonardo Souza** como projeto de cibersegurança pessoal.

---

> 💡 **Nota:** Este projeto foi desenvolvido para fins educativos e de monitorização da própria rede. A utilização desta ferramenta em redes de terceiros sem autorização expressa é ilegal e antiética.
