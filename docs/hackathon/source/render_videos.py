from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


WIDTH = 1920
HEIGHT = 1080
FPS = 30
BACKGROUND = "#071521"
PANEL = "#0d2434"
PANEL_ALT = "#123148"
WHITE = "#f4f8fb"
MUTED = "#a9bfd0"
CYAN = "#45d4ff"
BLUE = "#2787ff"
GREEN = "#5ee6a8"
AMBER = "#ffc857"
RED = "#ff6b72"


@dataclass(frozen=True)
class Pitch:
    folder: Path
    config: dict[str, Any]

    @property
    def scenes(self) -> list[dict[str, Any]]:
        return self.config["scenes"]

    @property
    def duration(self) -> int:
        return sum(int(scene["duration"]) for scene in self.scenes)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        Path("C:/Windows/Fonts/seguisb.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else
             "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def wrap(draw: ImageDraw.ImageDraw, text: str, selected_font: ImageFont.ImageFont,
         max_width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        width = draw.textbbox((0, 0), candidate, font=selected_font)[2]
        if width <= max_width or not current:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def draw_lines(draw: ImageDraw.ImageDraw, xy: tuple[int, int], lines: list[str],
               selected_font: ImageFont.ImageFont, fill: str, spacing: int) -> int:
    x, y = xy
    for line in lines:
        draw.text((x, y), line, font=selected_font, fill=fill)
        y += spacing
    return y


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], fill: str,
            outline: str | None = None, width: int = 2, radius: int = 24) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def draw_header(draw: ImageDraw.ImageDraw, pitch: Pitch, scene: dict[str, Any],
                scene_number: int, start: int, end: int, variant: str) -> None:
    draw.text((90, 55), scene["kicker"], font=font(26, bold=True), fill=CYAN)
    draw.text((1830, 57), pitch.config["audience"], anchor="ra", font=font(22), fill=MUTED)
    draw.line((90, 105, 1830, 105), fill="#224257", width=2)
    if variant == "draft":
        rounded(draw, (90, 930, 660, 1000), PANEL_ALT, CYAN, 2, 18)
        label = f"DRAFT STORYBOARD  |  SCENE {scene_number}  |  {start // 60}:{start % 60:02d}-{end // 60}:{end % 60:02d}"
        draw.text((118, 951), label, font=font(22, bold=True), fill=WHITE)


def draw_title_block(draw: ImageDraw.ImageDraw, scene: dict[str, Any]) -> None:
    title_font = font(67, bold=True)
    subtitle_font = font(35)
    title_lines = wrap(draw, scene["title"], title_font, 970)
    y = draw_lines(draw, (90, 175), title_lines, title_font, WHITE, 78)
    y += 28
    subtitle_lines = wrap(draw, scene["subtitle"], subtitle_font, 960)
    y = draw_lines(draw, (90, y), subtitle_lines, subtitle_font, MUTED, 48)
    y += 35
    for bullet in scene.get("bullets", []):
        draw.ellipse((95, y + 9, 111, y + 25), fill=CYAN)
        bullet_lines = wrap(draw, bullet, font(28), 870)
        y = draw_lines(draw, (132, y), bullet_lines, font(28), WHITE, 38) + 12


def draw_signal_visual(draw: ImageDraw.ImageDraw, labels: list[str]) -> None:
    center = (1460, 535)
    rounded(draw, (1305, 430, 1615, 640), PANEL_ALT, CYAN, 3, 28)
    draw.text(center, "WORKLOAD?", anchor="mm", font=font(34, bold=True), fill=WHITE)
    positions = [(1150, 250), (1460, 205), (1740, 300), (1750, 705), (1450, 805), (1150, 720)]
    for index, label in enumerate(labels[:6]):
        x, y = positions[index]
        rounded(draw, (x - 120, y - 45, x + 120, y + 45), PANEL, "#335d76", 2, 18)
        draw.text((x, y), label.upper(), anchor="mm", font=font(22, bold=True), fill=MUTED)
        draw.line((x, y + (45 if y < center[1] else -45), center[0], center[1]),
                  fill="#31536a", width=3)


def draw_context_visual(draw: ImageDraw.ImageDraw, labels: list[str]) -> None:
    rounded(draw, (1110, 185, 1810, 860), PANEL, "#31536a", 2, 32)
    draw.text((1460, 250), "GOVERNED WORKLOAD CONTEXT", anchor="mm",
              font=font(29, bold=True), fill=CYAN)
    rows = labels[:4] if labels else ["Identity", "Dependencies", "Objectives", "Guidance"]
    for index, label in enumerate(rows):
        y = 335 + index * 112
        color = [BLUE, GREEN, AMBER, CYAN][index % 4]
        rounded(draw, (1190, y, 1730, y + 78), PANEL_ALT, color, 2, 18)
        draw.text((1240, y + 39), label, anchor="lm", font=font(27, bold=True), fill=WHITE)
        draw.ellipse((1650, y + 25, 1680, y + 55), fill=color)


def draw_capture_visual(draw: ImageDraw.ImageDraw, scene: dict[str, Any], variant: str) -> None:
    box = (1080, 175, 1825, 855)
    rounded(draw, box, "#0a1d2b", AMBER, 4, 30)
    for offset in range(0, 36, 12):
        draw.line((1105 + offset, 200, 1140 + offset, 200), fill=AMBER, width=3)
    draw.text((1452, 430), "LIVE CAPTURE", anchor="mm", font=font(50, bold=True), fill=AMBER)
    label = scene.get("captureLabel", "Replace with approved live capture")
    lines = wrap(draw, label, font(30), 600)
    draw_lines(draw, (1160, 500), lines, font(30), WHITE, 42)
    draw.text((1452, 735), "Synthetic-safe data only", anchor="mm", font=font(24), fill=MUTED)
    if variant == "placeholder":
        rounded(draw, (1240, 790, 1665, 840), AMBER, None, radius=14)
        draw.text((1452, 815), "CAPTURE PLACEHOLDER", anchor="mm",
                  font=font(22, bold=True), fill=BACKGROUND)


def draw_platform_visual(draw: ImageDraw.ImageDraw) -> None:
    left = (1200, 285, 1430, 730)
    middle = (1480, 285, 1710, 730)
    for box, heading, items, color in [
        (left, "AZURE EVIDENCE", ["Azure MCP", "Monitor", "Health", "Changes"], BLUE),
        (middle, "ATHENA", ["Context", "Policy", "Judgment", "Guidance"], CYAN),
    ]:
        rounded(draw, box, PANEL, color, 3, 24)
        draw.text(((box[0] + box[2]) // 2, box[1] + 55), heading, anchor="mm",
                  font=font(24, bold=True), fill=color)
        for index, item in enumerate(items):
            y = box[1] + 130 + index * 70
            draw.text((box[0] + 32, y), item, font=font(25), fill=WHITE)
    draw.line((1430, 505, 1480, 505), fill=GREEN, width=8)
    draw.polygon([(1480, 505), (1455, 488), (1455, 522)], fill=GREEN)


def draw_ask_visual(draw: ImageDraw.ImageDraw, labels: list[str]) -> None:
    for index, label in enumerate(labels[:3]):
        y = 265 + index * 175
        rounded(draw, (1120, y, 1800, y + 125), PANEL, [BLUE, CYAN, GREEN][index], 3, 24)
        draw.text((1180, y + 62), label, anchor="lm", font=font(30, bold=True), fill=WHITE)


def render_frame(pitch: Pitch, scene: dict[str, Any], scene_number: int,
                 start: int, end: int, variant: str, output: Path) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, WIDTH, 18), fill=BLUE)
    draw_header(draw, pitch, scene, scene_number, start, end, variant)
    draw_title_block(draw, scene)

    visual = scene.get("visual", "title")
    if visual == "signals":
        draw_signal_visual(draw, scene.get("bullets", []))
    elif visual == "context":
        draw_context_visual(draw, scene.get("bullets", []))
    elif visual == "capture":
        draw_capture_visual(draw, scene, variant)
    elif visual == "platform":
        draw_platform_visual(draw)
    elif visual == "ask":
        draw_ask_visual(draw, scene.get("bullets", []))
    elif visual in {"title", "close"}:
        draw.ellipse((1240, 260, 1730, 750), outline=CYAN, width=5)
        draw.ellipse((1320, 340, 1650, 670), outline=BLUE, width=4)
        draw.line((1180, 505, 1790, 505), fill="#244d65", width=3)
        draw.text((1485, 505), "ATHENA", anchor="mm", font=font(46, bold=True), fill=WHITE)

    draw.text((90, 1030), "ATHENA WORKLOAD INTELLIGENCE", font=font(20, bold=True), fill=MUTED)
    draw.text((1830, 1030), "SILENT VIDEO | NARRATION SUPPLIED SEPARATELY", anchor="ra",
              font=font(20), fill=MUTED)
    image.save(output, "PNG", optimize=True)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)


def verify_output(path: Path, expected_duration: int, maximum: int) -> None:
    probe = run([
        "ffprobe", "-v", "error", "-show_entries",
        "format=duration:stream=codec_type,codec_name,width,height",
        "-of", "json", str(path),
    ])
    data = json.loads(probe.stdout)
    duration = float(data["format"]["duration"])
    streams = data["streams"]
    video_streams = [stream for stream in streams if stream["codec_type"] == "video"]
    audio_streams = [stream for stream in streams if stream["codec_type"] == "audio"]
    if len(video_streams) != 1 or audio_streams:
        raise RuntimeError(f"{path.name} must contain one video stream and no audio streams")
    video = video_streams[0]
    if video.get("codec_name") != "h264" or video.get("width") != WIDTH or video.get("height") != HEIGHT:
        raise RuntimeError(f"{path.name} is not a 1920x1080 H.264 video")
    if duration > maximum:
        raise RuntimeError(f"{path.name} duration {duration:.3f}s exceeds {maximum}s")
    if abs(duration - expected_duration) > 0.25:
        raise RuntimeError(
            f"{path.name} duration {duration:.3f}s differs from scene plan {expected_duration}s"
        )
    print(f"verified {path.name}: {duration:.3f}s, 1920x1080 H.264, silent")


def render_pitch(pitch: Pitch, variant: str) -> Path:
    output_dir = pitch.folder / "video"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{pitch.config['outputStem']}-{variant}.mp4"

    with tempfile.TemporaryDirectory(prefix=f"athena-{pitch.config['id']}-") as temporary:
        temp = Path(temporary)
        ffmpeg_inputs: list[str] = []
        filter_parts: list[str] = []
        elapsed = 0
        for index, scene in enumerate(pitch.scenes, start=1):
            duration = int(scene["duration"])
            frame = temp / f"scene-{index:02d}.png"
            render_frame(pitch, scene, index, elapsed, elapsed + duration, variant, frame)
            ffmpeg_inputs.extend([
                "-loop", "1", "-framerate", str(FPS), "-t", str(duration), "-i", str(frame),
            ])
            filter_parts.append(
                f"[{index - 1}:v]fps={FPS},format=yuv420p,setpts=PTS-STARTPTS[v{index - 1}]"
            )
            elapsed += duration
        labels = "".join(f"[v{index}]" for index in range(len(pitch.scenes)))
        filter_parts.append(f"{labels}concat=n={len(pitch.scenes)}:v=1:a=0[outv]")
        run([
            "ffmpeg", "-y", "-v", "error", *ffmpeg_inputs,
            "-filter_complex", ";".join(filter_parts), "-map", "[outv]",
            "-c:v", "libx264", "-preset", "medium", "-crf", "21",
            "-movflags", "+faststart", "-an", str(output),
        ])

    verify_output(output, pitch.duration, int(pitch.config["maxDurationSeconds"]))
    return output


def load_pitch(folder: Path) -> Pitch:
    config_path = folder / "source" / "scenes.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    scenes = config.get("scenes")
    if not isinstance(scenes, list) or not scenes:
        raise RuntimeError(f"{config_path} must contain a non-empty scenes array")
    for index, scene in enumerate(scenes, start=1):
        required = {"duration", "kicker", "title", "subtitle", "bullets", "visual"}
        missing = required - set(scene)
        if missing:
            raise RuntimeError(f"{config_path} scene {index} is missing {sorted(missing)}")
        if not isinstance(scene["duration"], int) or scene["duration"] <= 0:
            raise RuntimeError(f"{config_path} scene {index} has an invalid duration")
    pitch = Pitch(folder=folder, config=config)
    if pitch.duration > int(config["maxDurationSeconds"]):
        raise RuntimeError(
            f"{config['id']} scene plan is {pitch.duration}s, exceeding "
            f"{config['maxDurationSeconds']}s"
        )
    return pitch


def main() -> None:
    parser = argparse.ArgumentParser(description="Render silent Athena hackathon pitch videos")
    parser.add_argument(
        "--pitch", choices=("all", "global", "azure"), default="all",
        help="render one pitch or both",
    )
    parser.add_argument(
        "--variant", choices=("all", "draft", "placeholder"), default="all",
        help="render storyboard drafts, near-final placeholders, or both",
    )
    args = parser.parse_args()

    if shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None:
        raise RuntimeError("FFmpeg and FFprobe must be available on PATH")

    hackathon = Path(__file__).resolve().parents[1]
    folders = {
        "global": hackathon / "global-hackathon-2min",
        "azure": hackathon / "azure-core-lt-3min",
    }
    selected = folders.values() if args.pitch == "all" else [folders[args.pitch]]
    variants = ("draft", "placeholder") if args.variant == "all" else (args.variant,)

    for folder in selected:
        pitch = load_pitch(folder)
        print(
            f"rendering {pitch.config['id']}: {pitch.duration}s of "
            f"{pitch.config['maxDurationSeconds']}s maximum"
        )
        for variant in variants:
            render_pitch(pitch, variant)


if __name__ == "__main__":
    main()
