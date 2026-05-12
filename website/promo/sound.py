"""
Production-grade sound design для MurNet promo (48 sec).

Слои:
  1. Brown noise drone — глубокий атмосферный фон
  2. Sub bass A1 (55Hz)    — низкий гул, слабый tremolo
  3. Bass A2 (110Hz)       — основной тон
  4. Mid E3 (164.81Hz)     — perfect fifth, гармония
  5. High shimmer A5 (880Hz) — слабый высокочастотный слой, slow LFO
  6. Impacts (sub-bass booms) — на ключевых cuts сцен
  7. Ticks (1500Hz пиксели)  — на появление элементов в mesh/use cases/stack
  8. Master fade in/out + soft compression

Все через ffmpeg lavfi (никаких внешних samples).
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

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


# Тайминги ключевых cuts (когда сцены меняются) — для impacts
IMPACT_TIMES = [0.3, 4.0, 8.0, 17.8, 27.8, 33.8, 38.8, 43.8]

# Тайминги ticks (появление узлов/cards) — short blips
TICK_TIMES = [
    # mesh nodes (S3, 8.5-11s)
    8.5, 8.7, 8.9, 9.0, 9.1, 9.3, 9.5, 9.7, 9.9, 10.1,
    10.3, 10.5, 10.7, 10.9, 11.0,
    # use cases (S4, 18.5-21.5)
    18.5, 19.5, 20.5, 21.5,
    # stack rows (S5, 28.3-29.5)
    28.3, 28.7, 29.1, 29.5,
    # values (S6)
    34.0, 34.7, 35.4, 36.1,
]


def build_filter(duration: float) -> str:
    """
    Собираем complex filtergraph: 5 ambient слоёв + N impacts + M ticks.
    Все микшуются в стерео, нормализуются, добавляется fade in/out.
    """
    layers = []

    # ── 1. Brown noise — atmospheric base ─────────────────────────────
    layers.append((
        f"anoisesrc=color=brown:duration={duration}:amplitude=0.4",
        "aformat=channel_layouts=stereo,"
        "volume=0.18,"
        "lowpass=f=400"  # отфильтруем высокие частоты для теплоты
    ))

    # ── 2. Sub bass A1 (55Hz) — низкий гул ────────────────────────────
    layers.append((
        f"sine=frequency=55:duration={duration}:sample_rate=48000",
        "aformat=channel_layouts=stereo,"
        "volume=0.20,"
        "tremolo=f=0.15:d=0.4"
    ))

    # ── 3. Bass A2 (110Hz) — главный тон ──────────────────────────────
    layers.append((
        f"sine=frequency=110:duration={duration}:sample_rate=48000",
        "aformat=channel_layouts=stereo,"
        "volume=0.12,"
        "tremolo=f=0.25:d=0.5"
    ))

    # ── 4. Perfect fifth E3 (164.81Hz) — гармония ─────────────────────
    layers.append((
        f"sine=frequency=164.81:duration={duration}:sample_rate=48000",
        "aformat=channel_layouts=stereo,"
        "volume=0.08,"
        "tremolo=f=0.3:d=0.4"
    ))

    # ── 5. High shimmer A5 (880Hz) — космическое мерцание ─────────────
    layers.append((
        f"sine=frequency=880:duration={duration}:sample_rate=48000",
        "aformat=channel_layouts=stereo,"
        "volume=0.04,"
        "tremolo=f=0.5:d=0.7,"
        "highpass=f=600"
    ))

    # ── 6. Impacts — sub-bass booms на cuts ───────────────────────────
    for t in IMPACT_TIMES:
        # 0.4 sec attack-release envelope, 40Hz sine
        layers.append((
            f"sine=frequency=40:duration=0.5:sample_rate=48000",
            "aformat=channel_layouts=stereo,"
            "volume=0.6,"
            f"adelay={int(t*1000)}|{int(t*1000)},"
            f"afade=t=in:st={t}:d=0.01,"
            f"afade=t=out:st={t+0.05}:d=0.45"
        ))

    # ── 7. Ticks — короткие clicks на появление элементов ─────────────
    for t in TICK_TIMES:
        layers.append((
            f"sine=frequency=1500:duration=0.1:sample_rate=48000",
            "aformat=channel_layouts=stereo,"
            "volume=0.15,"
            f"adelay={int(t*1000)}|{int(t*1000)},"
            f"afade=t=in:st={t}:d=0.001,"
            f"afade=t=out:st={t+0.005}:d=0.08"
        ))

    # ── собираем filter graph ─────────────────────────────────────────
    inputs = []
    chains = []
    labels = []
    for i, (src, proc) in enumerate(layers):
        inputs.extend(["-f", "lavfi", "-i", src])
        chains.append(f"[{i}:a]{proc}[a{i}]")
        labels.append(f"[a{i}]")

    mix = "".join(labels) + f"amix=inputs={len(layers)}:duration=longest:normalize=0"

    master = (
        f"{mix},"
        # soft compression — выравниваем динамику
        "acompressor=threshold=-18dB:ratio=3:attack=20:release=200,"
        # subtle low-shelf boost для теплоты
        "equalizer=f=80:t=q:w=1.5:g=2,"
        # high cut от резкости
        "lowpass=f=15000,"
        # global fade in/out
        f"afade=t=in:st=0:d=1.5,"
        f"afade=t=out:st={duration-2}:d=2,"
        # final limiter
        "alimiter=limit=0.95"
        "[out]"
    )

    filter_complex = ";".join(chains) + ";" + master
    return inputs, filter_complex


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--duration", type=float, default=48.0)
    p.add_argument("--out",      default=str(Path(__file__).parent / "out" / "audio.wav"))
    args = p.parse_args()

    ff = find_ffmpeg()
    print(f"→ ffmpeg: {ff}")

    inputs, filter_complex = build_filter(args.duration)

    out_path = Path(args.out)
    out_path.parent.mkdir(exist_ok=True, parents=True)

    cmd = [
        ff, "-y",
        *inputs,
        "-filter_complex", filter_complex,
        "-map", "[out]",
        "-t", str(args.duration),
        "-ar", "48000",
        "-ac", "2",
        "-c:a", "pcm_s16le",
        str(out_path),
    ]
    print(f"→ building {len(inputs)//4} layers, total {args.duration}s")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("! ffmpeg failed:")
        print(result.stderr[-1500:])
        return 1
    size_mb = out_path.stat().st_size / 1024 / 1024
    print(f"✓ {out_path.name} — {size_mb:.1f} MB, 48kHz stereo PCM")
    return 0


if __name__ == "__main__":
    sys.exit(main())
