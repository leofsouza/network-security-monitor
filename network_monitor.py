"""
Network Security Monitor
========================
Ferramenta de monitorização de rede em tempo real que deteta:
- Novos dispositivos conectados à rede
- Portas perigosas abertas (RDP, SSH, Telnet, SMB, VNC, etc.)
- Alterações na topologia da rede local

Alertas automáticos por e-mail com relatório HTML detalhado.

Licença: MIT
"""

import nmap
import json
import smtplib
import socket
import logging
import os
import re
import subprocess
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ──────────────────────────────────────────────
# CONFIGURAÇÕES — edite antes de executar
# ──────────────────────────────────────────────

# Sub-redes a varrer
# Corre 'ipconfig' (Windows) ou 'ip a' (Linux) para descobrir a tua sub-rede
SUBNETS = [
    "192.168.1.0/24",   # Rede principal — ajusta conforme a tua rede
    # "192.168.0.0/24", # Sub-rede adicional (descomenta se necessário)
]

# Portas consideradas perigosas (geram alerta se abertas em dispositivos novos)
PORTAS_PERIGOSAS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}

# Dispositivos conhecidos e aprovados na tua rede (não geram alertas)
# Preenche após a primeira execução com os teus dispositivos legítimos
# Dica: usa IPs fixos ou configura reservas DHCP no router
DISPOSITIVOS_APROVADOS = {
    # "192.168.1.1":  "Router Principal",
    # "192.168.1.2":  "Smart TV",
    # "192.168.1.10": "Meu PC",
    # "192.168.1.20": "iPhone",
}

# ── Configurações de e-mail ──────────────────
# Gmail: cria uma App Password em myaccount.google.com/apppasswords
EMAIL_REMETENTE    = "teu-email@gmail.com"
EMAIL_SENHA        = "xxxxxxxxxxxxxxxx"      # App Password (16 caracteres sem espaços)
EMAIL_DESTINATARIO = "destino@email.com"
SMTP_HOST          = "smtp.gmail.com"
SMTP_PORT          = 587

# ── Ficheiros de dados e log ─────────────────
PASTA_DADOS    = os.path.dirname(os.path.abspath(__file__))
FICHEIRO_HOJE  = os.path.join(PASTA_DADOS, "scan_hoje.json")
FICHEIRO_ONTEM = os.path.join(PASTA_DADOS, "scan_ontem.json")
FICHEIRO_LOG   = os.path.join(PASTA_DADOS, "network_monitor.log")

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(FICHEIRO_LOG, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# WI-FI E FABRICANTE
# ──────────────────────────────────────────────

def obter_ssids_windows() -> dict:
    """
    Devolve um dicionário {subnet_prefix: ssid} com os SSIDs Wi-Fi ativos no Windows.
    Ex: {"192.168.1": "MinhaRede"}
    """
    ssids = {}
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="cp850", errors="replace"
        )
        blocos = output.split("\n\n")
        for bloco in blocos:
            ssid_match = re.search(r"SSID\s*:\s*(.+)", bloco)
            if ssid_match:
                ssid = ssid_match.group(1).strip()
                for subnet in SUBNETS:
                    prefixo = ".".join(subnet.split(".")[:3])
                    ssids[prefixo] = ssid
    except Exception:
        pass
    return ssids


def obter_fabricante_mac(mac: str) -> str:
    """
    Identifica o fabricante pelo prefixo do MAC address (OUI).
    Baseado numa lista local dos fabricantes mais comuns.
    """
    if not mac or mac == "desconhecido":
        return "Desconhecido"

    prefixo = mac.upper().replace("-", ":")[0:8]

    fabricantes = {
        # Routers e equipamentos de rede
        "A8:6E:84": "Huawei",
        "EC:B5:FA": "TP-Link",
        "50:C7:BF": "TP-Link",
        "C0:25:E9": "TP-Link",
        "18:D6:C7": "TP-Link",
        "30:DE:4B": "Asus",
        "04:92:26": "Asus",
        "00:90:F5": "Netgear",
        "28:80:88": "Netgear",
        # PCs e laptops
        "90:91:64": "Realtek (PC/Laptop)",
        "34:5A:60": "Realtek (PC/Laptop)",
        # Dispositivos móveis
        "AC:22:0B": "Apple",
        "F4:5C:89": "Apple",
        "3C:22:FB": "Apple",
        "18:65:90": "Apple",
        "40:4E:36": "Samsung",
        "8C:77:12": "Samsung",
        "70:1A:04": "Xiaomi",
        "64:09:80": "Xiaomi",
        # Dispositivos domésticos
        "74:51:BA": "Amazon (Echo/Alexa)",
        "FC:65:DE": "Amazon (Echo/Alexa)",
        "B4:7C:9C": "Google (Chromecast)",
        "F4:F5:D8": "Google (Nest)",
        "00:17:88": "Philips (Hue)",
        # Virtuais
        "0A:00:27": "VirtualBox",
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "02:00:4C": "Npcap (Virtual)",
    }

    return fabricantes.get(prefixo, "Desconhecido")


# ──────────────────────────────────────────────
# VARREDURA DE REDE
# ──────────────────────────────────────────────

def obter_hostname(ip: str) -> str:
    """Tenta resolver o hostname de um IP via DNS reverso."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "desconhecido"


def varrer_rede(subnets: list) -> dict:
    """
    Faz ping sweep + port scan básico em todas as sub-redes configuradas.
    Retorna dicionário com os hosts ativos e as suas portas abertas.
    """
    nm = nmap.PortScanner()
    portas_str = ",".join(str(p) for p in PORTAS_PERIGOSAS.keys())
    ssids = obter_ssids_windows()
    resultados = {}

    for subnet in subnets:
        prefixo = ".".join(subnet.split(".")[:3])
        ssid = ssids.get(prefixo, "Desconhecido")
        log.info(f"A varrer {subnet} (Wi-Fi: {ssid})...")

        # Fase 1 — Ping sweep para encontrar hosts ativos
        log.info("  Fase 1: Ping sweep...")
        nm.scan(hosts=subnet, arguments="-sn --host-timeout 2s -T5")
        hosts_ativos = nm.all_hosts()
        log.info(f"  {len(hosts_ativos)} host(s) ativo(s) encontrado(s).")

        # Fase 2 — Port scan nas portas perigosas
        log.info(f"  Fase 2: Port scan nas portas {portas_str}...")

        for ip in hosts_ativos:
            try:
                nm.scan(hosts=ip, arguments=f"-p {portas_str} -T5 --host-timeout 5s")
                portas_abertas = []

                if ip in nm.all_hosts():
                    for proto in nm[ip].all_protocols():
                        for porta in nm[ip][proto].keys():
                            if nm[ip][proto][porta]["state"] == "open":
                                nome = PORTAS_PERIGOSAS.get(porta, "desconhecida")
                                portas_abertas.append({"porta": porta, "servico": nome})

                mac = "desconhecido"
                try:
                    if "mac" in nm[ip].get("addresses", {}):
                        mac = nm[ip]["addresses"]["mac"]
                except Exception:
                    pass

                fabricante = obter_fabricante_mac(mac)
                hostname   = obter_hostname(ip)

                resultados[ip] = {
                    "ip":             ip,
                    "hostname":       hostname,
                    "mac":            mac,
                    "fabricante":     fabricante,
                    "ssid":           ssid,
                    "subnet":         subnet,
                    "portas_abertas": portas_abertas,
                    "timestamp":      datetime.now().isoformat(),
                }

                status_portas = ", ".join(f"{p['porta']}/{p['servico']}" for p in portas_abertas) or "nenhuma"
                log.info(f"  {ip} ({hostname}) | {fabricante} | MAC: {mac} | Portas: {status_portas}")

            except Exception as e:
                log.warning(f"  Erro ao varrer {ip}: {e}")

    return resultados


# ──────────────────────────────────────────────
# COMPARAÇÃO DE RESULTADOS
# ──────────────────────────────────────────────

def carregar_scan_anterior() -> dict:
    """Carrega os resultados do scan do dia anterior."""
    if os.path.exists(FICHEIRO_ONTEM):
        with open(FICHEIRO_ONTEM, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def guardar_scan_atual(resultados: dict):
    """Guarda os resultados atuais (hoje vira ontem na próxima execução)."""
    if os.path.exists(FICHEIRO_HOJE):
        os.replace(FICHEIRO_HOJE, FICHEIRO_ONTEM)
    with open(FICHEIRO_HOJE, "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)


def comparar_scans(atual: dict, anterior: dict) -> dict:
    """
    Compara os dois scans e devolve:
    - Novos dispositivos (excluindo aprovados)
    - Dispositivos que desapareceram
    - Novas portas perigosas abertas em dispositivos não aprovados
    """
    ips_atuais     = set(atual.keys())
    ips_anteriores = set(anterior.keys())
    ips_aprovados  = set(DISPOSITIVOS_APROVADOS.keys())

    novos         = (ips_atuais - ips_anteriores) - ips_aprovados
    desaparecidos = ips_anteriores - ips_atuais
    novas_portas  = {}

    for ip in ips_atuais & ips_anteriores:
        if ip in ips_aprovados:
            continue
        portas_agora = {p["porta"] for p in atual[ip]["portas_abertas"]}
        portas_antes = {p["porta"] for p in anterior[ip].get("portas_abertas", [])}
        portas_novas = portas_agora - portas_antes

        if portas_novas:
            novas_portas[ip] = {
                "hostname": atual[ip]["hostname"],
                "portas": [{"porta": p, "servico": PORTAS_PERIGOSAS.get(p, "?")} for p in portas_novas]
            }

    return {
        "novos_dispositivos":         {ip: atual[ip] for ip in novos},
        "dispositivos_desaparecidos": {ip: anterior[ip] for ip in desaparecidos},
        "novas_portas_perigosas":     novas_portas,
    }


# ──────────────────────────────────────────────
# E-MAIL
# ──────────────────────────────────────────────

def construir_corpo_email(scan_atual: dict, diferencas: dict) -> str:
    """Constrói o corpo HTML do e-mail de relatório."""
    agora         = datetime.now().strftime("%Y-%m-%d %H:%M")
    novos         = diferencas["novos_dispositivos"]
    desaparecidos = diferencas["dispositivos_desaparecidos"]
    novas_portas  = diferencas["novas_portas_perigosas"]
    tem_alertas   = bool(novos or novas_portas)
    cor_titulo    = "#c0392b" if tem_alertas else "#27ae60"
    titulo        = "🚨 ALERTA — Novos dispositivos/portas detetados" if tem_alertas else "✅ Relatório diário — Rede normal"

    linhas = ""
    for ip, info in sorted(scan_atual.items()):
        portas     = ", ".join(f"{p['porta']}/{p['servico']}" for p in info["portas_abertas"]) or "—"
        novo_badge = ' <span style="background:#e74c3c;color:white;padding:2px 6px;border-radius:3px;font-size:11px;">NOVO</span>' if ip in novos else ""
        cor_linha  = "#fff5f5" if ip in novos else "white"
        linhas += f"""
        <tr style="background:{cor_linha};">
          <td style="padding:6px 10px;">{ip}{novo_badge}</td>
          <td style="padding:6px 10px;">{info['hostname']}</td>
          <td style="padding:6px 10px;">{info.get('fabricante','—')}</td>
          <td style="padding:6px 10px;">{info['mac']}</td>
          <td style="padding:6px 10px;">📶 {info.get('ssid','—')}</td>
          <td style="padding:6px 10px;">{portas}</td>
        </tr>"""

    secao_alertas = ""
    if novos:
        lista = "".join(
            f"<li><strong>{ip}</strong> — {d['hostname']} | {d.get('fabricante','?')} | MAC: {d['mac']} | Wi-Fi: {d.get('ssid','?')}</li>"
            for ip, d in novos.items()
        )
        secao_alertas += f"<h3 style='color:#e74c3c;'>🆕 Novos Dispositivos Detetados</h3><ul>{lista}</ul>"

    if novas_portas:
        lista = "".join(
            f"<li>{ip} ({i['hostname']}) — <strong>{', '.join(f\"{p['porta']}/{p['servico']}\" for p in i['portas'])}</strong></li>"
            for ip, i in novas_portas.items()
        )
        secao_alertas += f"<h3 style='color:#e67e22;'>⚠️ Novas Portas Perigosas Abertas</h3><ul>{lista}</ul>"

    if desaparecidos:
        lista = "".join(
            f"<li>{ip} — {d['hostname']} ({d.get('fabricante','?')})</li>"
            for ip, d in desaparecidos.items()
        )
        secao_alertas += f"<h3 style='color:#7f8c8d;'>📴 Dispositivos Desaparecidos</h3><ul>{lista}</ul>"

    subnets_str = ", ".join(SUBNETS)

    return f"""
    <html><body style="font-family:Arial,sans-serif;max-width:900px;margin:auto;">
      <h2 style="background:{cor_titulo};color:white;padding:12px 16px;border-radius:6px;">{titulo}</h2>
      <p>Data/Hora: <strong>{agora}</strong> | Sub-redes: <strong>{subnets_str}</strong> | Dispositivos ativos: <strong>{len(scan_atual)}</strong></p>
      {secao_alertas if secao_alertas else '<p style="color:#27ae60;">✅ Nenhuma alteração detetada desde o último scan.</p>'}
      <h3>📋 Todos os Dispositivos na Rede</h3>
      <table border="1" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:13px;">
        <tr style="background:#2c3e50;color:white;">
          <th style="padding:8px 10px;">IP</th>
          <th style="padding:8px 10px;">Hostname</th>
          <th style="padding:8px 10px;">Fabricante</th>
          <th style="padding:8px 10px;">MAC</th>
          <th style="padding:8px 10px;">Wi-Fi (SSID)</th>
          <th style="padding:8px 10px;">Portas Abertas</th>
        </tr>
        {linhas}
      </table>
      <p style="color:#95a5a6;font-size:11px;margin-top:20px;">Gerado automaticamente pelo Network Security Monitor</p>
    </body></html>
    """


def enviar_email(scan_atual: dict, diferencas: dict):
    """Envia o relatório por e-mail."""
    tem_alertas = bool(diferencas["novos_dispositivos"] or diferencas["novas_portas_perigosas"])
    assunto = (
        f"🚨 [ALERTA REDE] Novos dispositivos detetados — {datetime.now().strftime('%Y-%m-%d')}"
        if tem_alertas else
        f"✅ [Relatório Rede] Scan diário — {datetime.now().strftime('%Y-%m-%d')}"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = assunto
    msg["From"]    = EMAIL_REMETENTE
    msg["To"]      = EMAIL_DESTINATARIO
    msg.attach(MIMEText(construir_corpo_email(scan_atual, diferencas), "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_REMETENTE, EMAIL_SENHA)
            smtp.send_message(msg)
        log.info(f"[✓] Relatório enviado para {EMAIL_DESTINATARIO}")
    except Exception as e:
        log.error(f"[ERRO] Falha ao enviar e-mail: {e}")


# ──────────────────────────────────────────────
# PONTO DE ENTRADA
# ──────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info(" Monitor de Rede — Início da Varredura")
    log.info("=" * 60)

    scan_anterior = carregar_scan_anterior()
    log.info(f"Scan anterior: {len(scan_anterior)} dispositivo(s) registado(s).")

    scan_atual = varrer_rede(SUBNETS)
    log.info(f"Scan atual: {len(scan_atual)} dispositivo(s) encontrado(s).")

    diferencas    = comparar_scans(scan_atual, scan_anterior)
    novos         = diferencas["novos_dispositivos"]
    novas_portas  = diferencas["novas_portas_perigosas"]
    desaparecidos = diferencas["dispositivos_desaparecidos"]

    if novos:
        log.warning(f"🆕 {len(novos)} novo(s) dispositivo(s): {', '.join(novos.keys())}")
    if novas_portas:
        log.warning(f"⚠️  Novas portas perigosas em: {', '.join(novas_portas.keys())}")
    if desaparecidos:
        log.info(f"📴 {len(desaparecidos)} dispositivo(s) desaparecido(s): {', '.join(desaparecidos.keys())}")
    if not novos and not novas_portas and not desaparecidos:
        log.info("✅ Nenhuma alteração detetada.")

    guardar_scan_atual(scan_atual)
    enviar_email(scan_atual, diferencas)

    log.info("=" * 60)
    log.info(" Varredura concluída.")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
