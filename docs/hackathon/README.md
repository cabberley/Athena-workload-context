# Athena hackathon pitch package

This package contains two silent pitch videos and separate Clipchamp-ready narration scripts for
Athena Workload Intelligence.

| Audience | Maximum | Draft target | Folder |
|---|---:|---:|---|
| Global Hackathon 2026, AI in Action: Operational Excellence | 2:00 | 1:57 | [`global-hackathon-2min`](global-hackathon-2min/) |
| Azure Core - Specialized Engineering LT | 3:00 | 2:56 | [`azure-core-lt-3min`](azure-core-lt-3min/) |

Both videos are designed to remain silent. Narration is maintained separately so it can be
generated with Clipchamp AI Voice and replaced without reworking the visual source.

## Current status

- Product name: **Athena Workload Intelligence**
- Presenter and team: **Chris Abberley - Principal Architect**
- One-line description: **We taught Azure what a workload actually is.**
- Recording freeze: **September 19, 2026**
- Global Hackathon upload deadline: **September 21, 2026 at 11:59 PM Pacific Time**
  (**September 22, 2026 at 4:59 PM Sydney time**)
- Approved names: Microsoft Azure, Azure MCP, and Epic
- Data policy: synthetic workload data only
- Current capability boundary: Athena converts governed workload context and live Azure evidence
  into explainable operational impact, bounded impact classification, ranked hypotheses, governed
  guidance availability, and verified recovery. PR-time prevention guardrails are not presented as
  implemented.

The generated placeholder videos deliberately mark the areas that require final live captures.
Measured outcomes remain placeholders until evidence is approved.

The final edit must use only capabilities verified in the September 19 capture environment. Each
capture checklist includes a fallback that preserves the claim boundary if an in-development
surface is not deployed by the freeze.

## Render the videos

Prerequisites:

- Python 3.14 or later
- Pillow
- FFmpeg and FFprobe on `PATH`

From the repository root:

```powershell
python .\docs\hackathon\source\render_videos.py
```

The renderer validates each scene plan, creates draft and near-final placeholder MP4s, checks the
maximum duration, and verifies that the outputs are silent 1920 x 1080 H.264 videos.

## Package structure

```text
docs/hackathon/
  global-hackathon-2min/
    source/scenes.json
    video/
    storyboard.md
    narration-script.md
    onscreen-copy.md
    capture-checklist.md
    submission-details.md
  azure-core-lt-3min/
    source/scenes.json
    video/
    storyboard.md
    narration-script.md
    onscreen-copy.md
    capture-checklist.md
    leadership-brief.md
  source/
    render_videos.py
```

Do not replace placeholders with customer data, production identifiers, credentials, unrestricted
logs, or unapproved internal material.
