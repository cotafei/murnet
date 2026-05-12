# MurNet — запустить свой ноут как Middle-узел БЕЗ port-forwarding.
#
# Как работает:
#   1) Стартуем home_relay.py локально на 127.0.0.1:9292
#   2) Запускаем SSH reverse tunnel к VDS: VDS:9290 -> мой_ноут:9292
#   3) Извне (для Guard'а) узел доступен через 80.93.52.15:9290
#   4) При разрыве — autossh / простой while-loop перезапускает туннель
#
# Никаких портов на роутере открывать не надо. Работает за CGNAT, через
# мобильный интернет, корпоративную сеть — везде где есть исходящий TCP/22.

$ErrorActionPreference = "Continue"
$MURNET   = "D:\kai\03_Projects\MURNET"
$KEY      = "D:\kai\02_System\vds_key"
$VDS      = "root@80.93.52.15"
$VDS_PORT = 9290                # порт на VDS, через который мы доступны
$NODE_PORT = 9292               # локальный порт home_relay.py
$NODE_NAME = $env:USERNAME + "-" + (Get-Random -Maximum 9999)

if (-not (Test-Path $KEY)) {
    Write-Host "! SSH key не найден: $KEY"
    exit 1
}

Write-Host "=================================="
Write-Host "  MurNet Home Node (reverse tunnel)"
Write-Host "=================================="
Write-Host "  Local relay : 127.0.0.1:$NODE_PORT"
Write-Host "  Public addr : 80.93.52.15:$VDS_PORT  (через SSH туннель)"
Write-Host "  Name        : $NODE_NAME"
Write-Host "=================================="

# 1) Запускаем home_relay.py локально (без public-IP detection — нам он не нужен)
Write-Host "[1/2] Стартую локальный middle relay..."
$relay = Start-Process -FilePath "python" `
    -ArgumentList @("-u", "$MURNET\home_relay.py", "--port", "$NODE_PORT", "--name", "$NODE_NAME", "--public-ip", "80.93.52.15") `
    -WorkingDirectory $MURNET `
    -PassThru `
    -RedirectStandardOutput "$MURNET\home_relay.log" `
    -RedirectStandardError  "$MURNET\home_relay.err" `
    -WindowStyle Hidden

Start-Sleep -Seconds 3
if ($relay.HasExited) {
    Write-Host "! home_relay.py упал. Лог:"
    Get-Content "$MURNET\home_relay.err" -Tail 10
    exit 2
}
Write-Host "  OK: PID $($relay.Id)"

# 2) SSH reverse tunnel — auto-reconnect
Write-Host "[2/2] Открываю SSH reverse tunnel..."
Write-Host "  Ctrl+C для остановки"
Write-Host ""

$attempt = 0
while ($true) {
    $attempt++
    Write-Host "[ssh] connect attempt $attempt — VDS:$VDS_PORT -> 127.0.0.1:$NODE_PORT"

    # -N: не запускать команду
    # -R: reverse forward — на VDS откроется порт $VDS_PORT, который форвардит на наш :NODE_PORT
    # 0.0.0.0:$VDS_PORT — слушать на ВСЕХ интерфейсах VDS, не только loopback (нужен GatewayPorts yes)
    # -o ServerAliveInterval=30 — пинг каждые 30с (детект разрыва)
    # -o ServerAliveCountMax=3 — после 3 неответных пингов рвём
    # -o ExitOnForwardFailure=yes — если порт занят, не висим тихо
    # -o StrictHostKeyChecking=no — не спрашивать про fingerprint
    ssh -i $KEY `
        -N -R "0.0.0.0:${VDS_PORT}:127.0.0.1:${NODE_PORT}" `
        -o ServerAliveInterval=30 `
        -o ServerAliveCountMax=3 `
        -o ExitOnForwardFailure=yes `
        -o StrictHostKeyChecking=no `
        $VDS

    $exitCode = $LASTEXITCODE
    Write-Host "[ssh] disconnected (exit $exitCode), reconnect in 5s..."
    Start-Sleep -Seconds 5

    if ($relay.HasExited) {
        Write-Host "[ssh] home_relay.py также умер, выхожу"
        exit 3
    }
}
