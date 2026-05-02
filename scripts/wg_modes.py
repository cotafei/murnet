"""
WireGuard режимы для телефона:

  python scripts/wg_modes.py full       -- весь трафик через VPN (текущий режим)
  python scripts/wg_modes.py bypass     -- только заблокированные RU-сайты через VPN
  python scripts/wg_modes.py whitelist  -- только сайты из whitelist.txt через VPN

Скрипт запускается локально, генерирует QR на рабочий стол.
Требует доступа к VDS через SSH (VDS_KEY).
"""
import subprocess, socket, sys, os, tempfile, ipaddress, urllib.request, json

VDS      = "80.93.52.15"
VDS_USER = "root"
VDS_KEY  = os.environ.get("VDS_KEY", "D:/kai/02_System/vds_key")
DESKTOP  = os.path.join(os.path.expanduser("~"), "Desktop")

SSH = ["ssh", "-i", VDS_KEY, "-o", "StrictHostKeyChecking=no",
       f"{VDS_USER}@{VDS}"]

# ─── helpers ──────────────────────────────────────────────────────────────────

def vds(cmd: str) -> str:
    r = subprocess.run(SSH + [cmd], capture_output=True, text=True, timeout=30)
    return r.stdout.strip()

def phone_keys() -> tuple[str, str]:
    pk  = vds("cat /etc/wireguard/phone_private.key")
    pub = vds("cat /etc/wireguard/server_public.key")
    return pk, pub

def make_config(allowed_ips: str) -> str:
    priv, srv_pub = phone_keys()
    return (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        "Address = 10.8.0.2/24\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        f"PublicKey = {srv_pub}\n"
        f"Endpoint = {VDS}:51820\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )

def upload_and_qr(config: str, mode: str) -> str:
    """Upload config to VDS, generate QR PNG, download to Desktop."""
    remote_cfg = f"/tmp/wg_phone_{mode}.conf"
    remote_png = f"/tmp/wg_phone_{mode}.png"
    local_png  = os.path.join(DESKTOP, f"murnet_vpn_{mode}.png")

    # Upload config
    proc = subprocess.Popen(
        ["scp", "-i", VDS_KEY, "-o", "StrictHostKeyChecking=no",
         "-", f"{VDS_USER}@{VDS}:{remote_cfg}"],
        stdin=subprocess.PIPE
    )
    proc.communicate(config.encode())

    # Generate QR on VDS
    vds(f"qrencode -t PNG -o {remote_png} -s 8 < {remote_cfg}")

    # Download to Desktop
    subprocess.run(
        ["scp", "-i", VDS_KEY, "-o", "StrictHostKeyChecking=no",
         f"{VDS_USER}@{VDS}:{remote_png}", local_png],
        check=True
    )
    return local_png

# ─── режимы ───────────────────────────────────────────────────────────────────

def mode_full():
    print("Режим: FULL — весь трафик через VPN")
    cfg  = make_config("0.0.0.0/0, ::/0")
    path = upload_and_qr(cfg, "full")
    print(f"QR сохранён: {path}")

def mode_bypass():
    """
    Скачиваем список заблокированных IP с antifilter.download.
    Только они идут через VPN — остальное напрямую (быстрее).
    """
    print("Режим: BYPASS — загружаю список заблокированных IP с antifilter.download …")

    url = "https://antifilter.download/list/subnet.lst"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            lines = r.read().decode().splitlines()
    except Exception as e:
        print(f"Не удалось скачать список: {e}")
        print("Используем резервный короткий список …")
        lines = _fallback_blocked()

    # Фильтруем валидные CIDR
    cidrs = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            cidrs.append(line)
        except ValueError:
            pass

    print(f"  Загружено {len(cidrs)} подсетей")

    # WireGuard AllowedIPs не может быть пустым
    if not cidrs:
        print("Список пустой — переключаюсь на full режим")
        mode_full()
        return

    allowed = ", ".join(cidrs)
    cfg  = make_config(allowed)
    path = upload_and_qr(cfg, "bypass")
    print(f"QR сохранён: {path}")
    print("Через VPN идут только заблокированные сайты. Остальное — напрямую.")

def mode_whitelist():
    """
    Читаем whitelist.txt (домены или CIDR, по одному на строку).
    Резолвим домены в IP, генерируем конфиг.
    """
    wl_file = os.path.join(os.path.dirname(__file__), "whitelist.txt")

    if not os.path.exists(wl_file):
        _create_example_whitelist(wl_file)
        print(f"Создан пример: {wl_file}")
        print("Отредактируй его и запусти снова.")
        return

    print(f"Режим: WHITELIST — читаю {wl_file} …")
    cidrs = set()

    with open(wl_file, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Проверяем — это CIDR или домен
            try:
                ipaddress.ip_network(line, strict=False)
                cidrs.add(line)
                continue
            except ValueError:
                pass
            # Это домен — резолвим
            try:
                infos = socket.getaddrinfo(line, None)
                for info in infos:
                    ip = info[4][0]
                    try:
                        net = ipaddress.ip_network(ip)
                        cidrs.add(str(net))
                        print(f"  {line} → {ip}")
                    except ValueError:
                        pass
            except socket.gaierror as e:
                print(f"  Не удалось разрезолвить {line}: {e}")

    if not cidrs:
        print("Список пустой. Проверь whitelist.txt")
        return

    print(f"  Итого: {len(cidrs)} IP-адресов/подсетей")
    allowed = ", ".join(sorted(cidrs))
    cfg  = make_config(allowed)
    path = upload_and_qr(cfg, "whitelist")
    print(f"QR сохранён: {path}")

# ─── вспомогательные ──────────────────────────────────────────────────────────

def _fallback_blocked() -> list[str]:
    """Минимальный резервный список если antifilter недоступен."""
    return [
        # YouTube
        "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
        # Instagram / Facebook
        "31.13.64.0/18", "157.240.0.0/17",
        # Twitter / X
        "104.244.42.0/21",
        # Telegram
        "91.108.4.0/22", "91.108.8.0/22", "91.108.56.0/22",
        "149.154.160.0/20",
    ]

def _create_example_whitelist(path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Whitelist — домены или CIDR, по одному на строку\n")
        f.write("# Только эти сайты будут идти через VPN\n\n")
        f.write("youtube.com\n")
        f.write("instagram.com\n")
        f.write("twitter.com\n")
        f.write("x.com\n")
        f.write("reddit.com\n")
        f.write("# 192.168.1.0/24\n")

# ─── main ─────────────────────────────────────────────────────────────────────

MODES = {"full": mode_full, "bypass": mode_bypass, "whitelist": mode_whitelist}

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in MODES:
        print("Использование:")
        print("  python scripts/wg_modes.py full       — весь трафик через VPN")
        print("  python scripts/wg_modes.py bypass     — только заблокированные через VPN")
        print("  python scripts/wg_modes.py whitelist  — только свой список через VPN")
        sys.exit(1)
    MODES[mode]()
