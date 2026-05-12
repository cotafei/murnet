"""
Detereminированная запись 60 fps через CDP virtual time.

Логика:
  - Замораживаем virtual time (страница НЕ обновляется по реальному часу)
  - В цикле: advance virtual time на 16.67ms → screenshot → save PNG
  - Получаем 60 идеально равномерных кадров на секунду, без drop frames

Результат: ~2940 PNG для 49 секунд, потом ffmpeg склеит в lossless mp4.

Использование:
    python record_smooth.py
"""
from __future__ import annotations

import asyncio
import base64
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from playwright.async_api import async_playwright

FPS       = 60
DURATION  = 49.0
WIDTH     = 1920
HEIGHT    = 1080
FRAMES_FMT = "frame_{i:06d}.png"

FFMPEG_LOCATIONS = [
    "ffmpeg",
    r"C:\Tools\ffmpeg\ffmpeg.exe",
    r"C:\Tools\ffmpeg\ffmpeg-8.1.1-essentials_build\bin\ffmpeg.exe",
]


def find_ffmpeg() -> str:
    for loc in FFMPEG_LOCATIONS:
        if shutil.which(loc) or Path(loc).exists():
            return loc
    raise FileNotFoundError("ffmpeg not found")


async def render_frames(promo: Path, frames_dir: Path) -> int:
    """JS-driven: seek-аем все Animation объекты на правильное время каждый кадр."""
    n_frames = int(DURATION * FPS)
    step_ms  = 1000.0 / FPS
    print(f"→ rendering {n_frames} frames @ {FPS}fps (JS animation seek)")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--hide-scrollbars",
                "--disable-web-security",
                "--force-device-scale-factor=1",
                "--enable-gpu-rasterization",
                "--ignore-gpu-blocklist",
                "--disable-software-rasterizer",
                "--font-render-hinting=none",
            ],
        )
        ctx  = await browser.new_context(viewport={"width": WIDTH, "height": HEIGHT})
        page = await ctx.new_page()
        client = await ctx.new_cdp_session(page)

        await page.goto(promo.as_uri(), wait_until="domcontentloaded")
        # ждём шрифты + первый paint
        await page.evaluate("document.fonts.ready")
        await page.wait_for_timeout(800)

        # Найти все Animation и поставить на pause — будем сами их двигать.
        await page.evaluate("""
            () => {
                window.__anims = document.getAnimations();
                window.__anims.forEach(a => { a.pause(); });
                console.log('paused', window.__anims.length, 'animations');
            }
        """)

        progress_step = max(1, n_frames // 20)
        for i in range(n_frames):
            t_ms = i * step_ms
            # seek все animations в нужный момент
            await page.evaluate(
                "t => { window.__anims.forEach(a => { try { a.currentTime = t; } catch(_){} }); }",
                t_ms,
            )
            # screenshot через CDP — быстрее чем page.screenshot
            data = await client.send("Page.captureScreenshot", {
                "format": "png",
                "captureBeyondViewport": False,
                "fromSurface": True,
            })
            png_bytes = base64.b64decode(data["data"])
            frame_path = frames_dir / FRAMES_FMT.format(i=i)
            frame_path.write_bytes(png_bytes)

            if (i + 1) % progress_step == 0 or i == n_frames - 1:
                pct = (i + 1) / n_frames * 100
                print(f"  {i+1}/{n_frames}  {pct:.0f}%")

        await browser.close()

    return n_frames


def build_audio(out: Path) -> Path:
    """Импортируем sound.py и генерируем audio.wav с громкостью x2."""
    sys.path.insert(0, str(Path(__file__).parent))
    from sound import build_filter

    ff = find_ffmpeg()
    inputs, filter_complex = build_filter(DURATION)
    # буст всего микса перед лимитером для громкости
    filter_complex = filter_complex.replace(
        "alimiter=limit=0.95",
        "volume=2.5,alimiter=limit=0.97"
    )

    audio = out / f"audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
    cmd = [
        ff, "-y",
        *inputs,
        "-filter_complex", filter_complex,
        "-map", "[out]",
        "-t", str(DURATION),
        "-ar", "48000", "-ac", "2", "-c:a", "pcm_s16le",
        str(audio),
    ]
    print(f"→ generating soundtrack")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("! audio failed:", r.stderr[-500:])
        raise RuntimeError("audio")
    print(f"  ✓ {audio.name}")
    return audio


def encode_mp4(frames_dir: Path, audio: Path, out_mp4: Path):
    """frames + audio → mp4. PNG sequence через ffmpeg."""
    ff = find_ffmpeg()
    pattern = str(frames_dir / "frame_%06d.png")
    print(f"→ encoding {FPS}fps mp4 (this is the slow part)")
    cmd = [
        ff, "-y",
        "-framerate", str(FPS),
        "-i", pattern,
        "-i", str(audio),
        "-c:v", "libx264", "-preset", "slow", "-crf", "16",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "256k",
        "-movflags", "+faststart",
        "-r", str(FPS),
        "-shortest",
        str(out_mp4),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("! encode failed:", r.stderr[-800:])
        raise RuntimeError("encode")
    size = out_mp4.stat().st_size / 1024 / 1024
    print(f"  ✓ {out_mp4.name} — {size:.1f} MB")


async def main() -> int:
    here  = Path(__file__).parent
    promo = here / "promo.html"
    out   = here / "out"
    out.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    frames_dir = out / f"frames_{ts}"
    frames_dir.mkdir(exist_ok=True)

    n = await render_frames(promo, frames_dir)
    audio = build_audio(out)
    mp4 = out / f"murnet_promo_{ts}_smooth.mp4"
    encode_mp4(frames_dir, audio, mp4)

    # cleanup frames dir
    shutil.rmtree(frames_dir)

    print()
    print(f"DONE: {mp4}")
    print(f"  {n} frames @ {FPS}fps virtual time (детерминированно)")
    print(f"  audio +200% volume vs предыдущей версии")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
