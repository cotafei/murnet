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

    # Write config to a local temp file, then scp it up
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                     delete=False, encoding="utf-8") as tf:
        tf.write(config)
        tmp_path = tf.name

    try:
        subprocess.run(
            ["scp", "-i", VDS_KEY, "-o", "StrictHostKeyChecking=no",
             tmp_path, f"{VDS_USER}@{VDS}:{remote_cfg}"],
            check=True, capture_output=True
        )
    finally:
        os.unlink(tmp_path)

    # Generate QR on VDS
    vds(f"qrencode -t PNG -o {remote_png} -s 8 < {remote_cfg}")

    # Download to Desktop
    subprocess.run(
        ["scp", "-i", VDS_KEY, "-o", "StrictHostKeyChecking=no",
         f"{VDS_USER}@{VDS}:{remote_png}", local_png],
        check=True, capture_output=True
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
    Качаем allyouneed.lst (15k подсетей) — список заблокированных в РФ.
    Конфиг слишком большой для QR — сохраняем .conf файл для прямого импорта.
    """
    print("Режим: BYPASS — загружаю allyouneed.lst с antifilter.download …")

    url = "https://antifilter.download/list/allyouneed.lst"
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            lines = r.read().decode().splitlines()
    except Exception as e:
        print(f"Не удалось скачать список: {e}")
        print("Используем резервный список ключевых сервисов …")
        lines = _fallback_blocked()

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

    # Принудительно добавляем YouTube/Telegram/Instagram — их нет в antifilter
    for cidr in MUST_HAVE:
        if cidr not in cidrs:
            cidrs.append(cidr)

    print(f"  Итого подсетей: {len(cidrs)} (antifilter + YouTube/Telegram/Instagram/Twitter)")

    if not cidrs:
        print("Список пустой — переключаюсь на full режим")
        mode_full()
        return

    allowed = ", ".join(cidrs)
    cfg  = make_config(allowed)

    # Список слишком большой для QR — сохраняем .conf напрямую
    local_conf = os.path.join(DESKTOP, "murnet_vpn_bypass.conf")
    with open(local_conf, "w", encoding="utf-8") as f:
        f.write(cfg)

    print(f"Конфиг сохранён: {local_conf}")
    print("")
    print("Как импортировать в WireGuard:")
    print("  Android: кнопка + > Импортировать из файла > выбери murnet_vpn_bypass.conf")
    print("  iOS:     передай файл через AirDrop/iCloud, открой в WireGuard")
    print("")
    print("Через VPN идут только заблокированные (~15к подсетей). Остальное напрямую.")

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

MUST_HAVE = [
    # YouTube / Google Video
    "142.250.0.0/15", "172.253.0.0/16", "172.217.0.0/16",
    "209.85.128.0/17", "216.58.192.0/19", "74.125.0.0/16",
    "64.233.160.0/19", "66.102.0.0/20", "173.194.0.0/16",
    # Telegram
    "91.108.4.0/22",  "91.108.8.0/22",  "91.108.12.0/22",
    "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22",
    "91.108.60.0/22", "149.154.160.0/20", "149.154.164.0/22",
    "5.28.195.0/24",
    # Instagram / Facebook
    "31.13.24.0/21", "31.13.64.0/18", "157.240.0.0/17",
    # Twitter / X
    "104.244.42.0/21",
    # Discord
    "66.22.192.0/18",
]

def _fallback_blocked() -> list[str]:
    """Резервный список если antifilter недоступен."""
    return MUST_HAVE

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
