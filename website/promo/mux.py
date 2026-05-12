"""
Финальный pipeline:
  1. Записать promo.html → webm (Playwright)
  2. Сгенерировать audio.wav (sound.py)
  3. ffmpeg muxes webm+audio → mp4 со звуком, плюс motion-blur для гладкости

Использование:
    python mux.py
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# reuse helpers
sys.path.insert(0, str(Path(__file__).parent))
from record import record_webm
from sound import find_ffmpeg, build_filter


FFMPEG = find_ffmpeg()


async def main() -> int:
    here = Path(__file__).parent
    promo = here / "promo.html"
    out   = here / "out"
    out.mkdir(exist_ok=True)

    duration = 49.0
    fps      = 60

    print("[1/3] recording webm via Playwright...")
    webm = await record_webm(promo, out, duration, 1920, 1080)

    print("[2/3] generating ambient soundtrack (8 layers)...")
    audio = out / f"audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
    inputs, filter_complex = build_filter(duration)
    audio_cmd = [
        FFMPEG, "-y",
        *inputs,
        "-filter_complex", filter_complex,
        "-map", "[out]",
        "-t", str(duration),
        "-ar", "48000", "-ac", "2", "-c:a", "pcm_s16le",
        str(audio),
    ]
    r = subprocess.run(audio_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-1500:])
        return 2
    print(f"  ✓ audio: {audio.name}")

    print(f"[3/3] muxing webm+audio → mp4 @ {fps}fps with motion blur...")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    mp4 = out / f"murnet_promo_{ts}_final.mp4"
    # tblend=average → межкадровое размытие (motion blur), gives smoothness
    # Without crazy minterpolate artifacts
    mux_cmd = [
        FFMPEG, "-y",
        "-i", str(webm),
        "-i", str(audio),
        "-filter_complex",
        f"[0:v]fps={fps},tblend=all_mode=average,framestep=1[v]",
        "-map", "[v]",
        "-map", "1:a",
        "-c:v", "libx264", "-preset", "slow", "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "192k",
        "-movflags", "+faststart",
        "-r", str(fps),
        "-shortest",
        str(mp4),
    ]
    r = subprocess.run(mux_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-2000:])
        return 3

    size = mp4.stat().st_size / 1024 / 1024
    print()
    print(f"DONE: {mp4}")
    print(f"  size:  {size:.1f} MB")
    print(f"  video: 1920x1080 @ {fps}fps H.264 CRF 18 + tblend motion smoothing")
    print(f"  audio: AAC 192k stereo 48kHz (8-layer ambient)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
