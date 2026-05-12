"""
Записать promo.html в MP4 через Playwright + ffmpeg.

Workflow:
  1. Playwright headless Chromium @ 1920x1080
  2. Открывает promo.html, записывает webm (CRF lossless from compositor)
  3. ffmpeg конвертирует webm → mp4 (H.264, CRF 18, faststart)

Использование:
    python record.py
    python record.py --duration 50 --width 1920 --height 1080
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import datetime

from playwright.async_api import async_playwright


async def record_webm(promo: Path, out: Path, duration: float,
                      width: int, height: int) -> Path:
    print(f"→ Chromium {width}x{height} headless, recording {duration}s...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--hide-scrollbars",
                "--disable-web-security",
                "--force-device-scale-factor=1",
                # GPU/compositor — выжимаем максимум fps
                "--enable-gpu-rasterization",
                "--enable-zero-copy",
                "--ignore-gpu-blocklist",
                "--disable-software-rasterizer",
                "--disable-frame-rate-limit",
                "--enable-features=VaapiVideoEncoder",
            ],
        )
        ctx = await browser.new_context(
            viewport={"width": width, "height": height},
            record_video_dir=str(out),
            record_video_size={"width": width, "height": height},
            device_scale_factor=1,
        )
        page = await ctx.new_page()
        await page.goto(promo.as_uri(), wait_until="domcontentloaded")
        await page.wait_for_timeout(800)   # fonts + initial paint
        await page.wait_for_timeout(int(duration * 1000))

        video = page.video
        await page.close()
        await ctx.close()
        await browser.close()

        src = Path(await video.path())
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = out / f"murnet_promo_{ts}.webm"
        src.rename(dst)
        print(f"  ✓ webm: {dst.name} ({dst.stat().st_size / 1024 / 1024:.1f} MB)")
        return dst


FFMPEG_LOCATIONS = [
    "ffmpeg",
    r"C:\Tools\ffmpeg\ffmpeg.exe",
    r"C:\Tools\ffmpeg\ffmpeg-8.1.1-essentials_build\bin\ffmpeg.exe",
]


def _find_ffmpeg() -> str | None:
    for loc in FFMPEG_LOCATIONS:
        if shutil.which(loc) or Path(loc).exists():
            return loc
    return None


def convert_to_mp4(webm: Path, target_fps: int = 120) -> Path | None:
    """webm → mp4 H.264 + motion-interpolation до target_fps fps.

    minterpolate с mci+bidir восстанавливает промежуточные кадры через
    motion estimation. Сравнимо с TVшным soap-opera effect — но управляемо.
    """
    ff = _find_ffmpeg()
    if not ff:
        print("! ffmpeg не найден")
        return None

    mp4 = webm.with_name(webm.stem + f"_{target_fps}fps.mp4")
    print(f"→ ffmpeg: webm → mp4 @ {target_fps}fps (motion-interpolated, may take 2-3 min)")
    cmd = [
        ff, "-y",
        "-i", str(webm),
        "-vf", f"minterpolate=fps={target_fps}:mi_mode=mci:me_mode=bidir:vsbmc=1:scd=none",
        "-c:v", "libx264",
        "-preset", "slow",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-movflags", "+faststart",
        "-r", str(target_fps),
        str(mp4),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ! ffmpeg failed:\n{result.stderr[-500:]}")
        return None
    print(f"  ✓ mp4: {mp4.name} ({mp4.stat().st_size / 1024 / 1024:.1f} MB)")
    return mp4


async def main(duration: float, width: int, height: int, keep_webm: bool, fps: int) -> int:
    here  = Path(__file__).parent
    promo = here / "promo.html"
    out   = here / "out"
    out.mkdir(exist_ok=True)

    if not promo.exists():
        print(f"! {promo} not found")
        return 1

    webm = await record_webm(promo, out, duration, width, height)
    mp4  = convert_to_mp4(webm, target_fps=fps)

    if mp4 and not keep_webm:
        webm.unlink()
        print(f"  - webm cleaned up")

    print()
    print(f"DONE: {mp4 or webm}")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--duration",  type=float, default=49.0, help="seconds")
    p.add_argument("--width",     type=int,   default=1920)
    p.add_argument("--height",    type=int,   default=1080)
    p.add_argument("--fps",       type=int,   default=120, help="target fps via motion-interpolation")
    p.add_argument("--keep-webm", action="store_true", help="don't delete intermediate webm")
    args = p.parse_args()
    sys.exit(asyncio.run(main(args.duration, args.width, args.height, args.keep_webm, args.fps)))
