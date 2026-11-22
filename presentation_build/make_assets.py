"""Generate custom high-DPI brand visuals and clean cropped UI screenshots."""

from pathlib import Path
import shutil
import math
import numpy as np
from PIL import Image, ImageDraw
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, Wedge, RegularPolygon

ROOT = Path(r"C:\Users\Microsoft Office\.gemini\antigravity\scratch\AGH")
OUT_DIR = ROOT / "presentation_build" / "assets"
OUT_DIR.mkdir(parents=True, exist_ok=True)

BROWSER_SHOTS = Path(
    r"C:\Users\Microsoft Office\.gemini\antigravity\brain\3c1a384a-f02e-4ea3-be20-1c1640070044\browser_sandbox\screenshots"
)

SCREENSHOT_MAP = {
    "ui_dashboard.png": ("step_8_shot_1_dashboard_full.png", True),
    "ui_hosts.png": ("step_10_shot_1_hosts_services_full.png", False),
    "ui_diffs.png": ("step_12_shot_1_diffs_changes_full.png", False),
    "ui_admin.png": ("step_16_shot_1_admin_rbac_full.png", True),
}


def prepare_screenshots() -> None:
    for dest_name, (src_name, crop_scrollbar) in SCREENSHOT_MAP.items():
        src = BROWSER_SHOTS / src_name
        dst = OUT_DIR / dest_name
        with Image.open(src) as im:
            w, h = im.size
            if crop_scrollbar:
                # Trim the 18px right-hand Windows scrollbar cleanly
                im = im.crop((0, 0, w - 18, h))
            im.save(dst, format="PNG", optimize=True)
            print(f"Prepared {dst.name}: {im.size}")


def render_asi_logo(size: int = 512) -> None:
    """Supersampled rasterization matching ui/public/favicon.svg geometry."""
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    def sc(v: float) -> float:
        return v * (s / 64.0)

    # Background square
    d.rectangle([sc(2), sc(2), sc(62), sc(62)], fill="#141414", outline="#3d3d3d", width=int(sc(2)))

    # Corner brackets (#f98406)
    cw = int(sc(3))
    brackets = [
        [(2, 12), (2, 2), (12, 2)],
        [(52, 2), (62, 2), (62, 12)],
        [(62, 52), (62, 62), (52, 62)],
        [(12, 62), (2, 62), (2, 52)],
    ]
    for pts in brackets:
        d.line([(sc(x), sc(y)) for x, y in pts], fill="#f98406", width=cw, joint="curve")

    # Shield polygon
    shield = [
        (32, 10),
        (50, 17),
        (50, 31),
        (48, 39),
        (42, 47),
        (32, 56),
        (22, 47),
        (16, 39),
        (14, 31),
        (14, 17),
    ]
    d.polygon([(sc(x), sc(y)) for x, y in shield], fill="#1c1c1c")
    d.line(
        [(sc(x), sc(y)) for x, y in shield + [shield[0]]],
        fill="#f98406",
        width=int(sc(3.5)),
        joint="curve",
    )

    # Dashed reticle circle
    cx, cy, r = sc(32), sc(31), sc(10)
    for deg in range(0, 360, 36):
        d.arc([cx - r, cy - r, cx + r, cy + r], start=deg, end=deg + 20, fill="#f98406", width=int(sc(2)))

    # Crosshair lines
    d.line([(sc(32), sc(17)), (sc(32), sc(45))], fill=(249, 132, 6, 190), width=int(sc(1.75)))
    d.line([(sc(18), sc(31)), (sc(46), sc(31))], fill=(249, 132, 6, 190), width=int(sc(1.75)))

    # Emerald sweep + node
    d.line([(sc(32), sc(31)), (sc(41), sc(22))], fill="#10b981", width=int(sc(2.5)))
    r_em = sc(3)
    d.ellipse([sc(41) - r_em, sc(22) - r_em, sc(41) + r_em, sc(22) + r_em], fill="#10b981")
    r_am = sc(2.5)
    d.ellipse([sc(32) - r_am, sc(31) - r_am, sc(32) + r_am, sc(31) + r_am], fill="#f98406")

    final = img.resize((size, size), Image.Resampling.LANCZOS)
    dst = OUT_DIR / "asi_logo.png"
    final.save(dst, format="PNG")
    print(f"Prepared {dst.name}: {final.size}")


def render_cover_radar() -> None:
    """Minimalist tactical attack-surface topology visualization for Slide 1."""
    fig, ax = plt.subplots(figsize=(7.5, 7.5), dpi=240)
    fig.patch.set_facecolor("#121316")
    ax.set_facecolor("#121316")
    ax.set_xlim(-1.30, 1.30)
    ax.set_ylim(-1.26, 1.26)
    ax.set_aspect("equal")
    ax.axis("off")

    # Subtle coordinate crosshair grid
    for val in [-0.8, -0.4, 0.0, 0.4, 0.8]:
        alpha = 0.22 if val == 0 else 0.08
        ax.axhline(val, color="#333842", linewidth=0.9, alpha=alpha, zorder=1)
        ax.axvline(val, color="#333842", linewidth=0.9, alpha=alpha, zorder=1)

    # Radar sweep wedge
    for step, a in [(0, 0.14), (10, 0.09), (22, 0.045), (36, 0.02)]:
        wedge = Wedge(
            (0, 0),
            0.96,
            28 + step,
            74,
            facecolor="#F98406",
            edgecolor="none",
            alpha=a,
            zorder=2,
        )
        ax.add_patch(wedge)

    # Concentric subnet rings
    radii = [0.24, 0.48, 0.72, 0.96]
    styles = [
        ("#F98406", 1.3, "--", 0.55),
        ("#38BDF8", 1.0, "-", 0.35),
        ("#333842", 1.1, "-", 0.85),
        ("#F98406", 1.5, "-", 0.60),
    ]
    for rad, (col, lw, ls, al) in zip(radii, styles):
        c = Circle((0, 0), rad, fill=False, edgecolor=col, linewidth=lw, linestyle=ls, alpha=al, zorder=3)
        ax.add_patch(c)

    # Outer compass ticks
    for deg in range(0, 360, 15):
        ang = math.radians(deg)
        r_in = 0.96 if deg % 45 != 0 else 0.92
        r_out = 1.01 if deg % 45 != 0 else 1.04
        col = "#F98406" if deg % 45 == 0 else "#4B5563"
        lw = 1.5 if deg % 45 == 0 else 0.8
        ax.plot(
            [r_in * math.cos(ang), r_out * math.cos(ang)],
            [r_in * math.sin(ang), r_out * math.sin(ang)],
            color=col,
            linewidth=lw,
            alpha=0.85,
            zorder=3,
        )

    # Subnet node coordinates (radius, angle_deg, color, size, label, dx, dy, ha)
    nodes = [
        (0.48, 42, "#10B981", 85, "ACTIVE :8080", 0.07, 0.05, "left"),
        (0.72, 64, "#F98406", 95, "DIFF +svc", 0.06, 0.06, "left"),
        (0.48, 128, "#38BDF8", 65, "TLS / SNI", -0.06, 0.06, "right"),
        (0.72, 168, "#10B981", 70, "HTTP :8888", -0.07, 0.04, "right"),
        (0.96, 208, "#EF4444", 80, "TARPIT >200", 0.07, -0.05, "left"),
        (0.48, 252, "#F59E0B", 75, "UNSTABLE", -0.06, -0.07, "right"),
        (0.72, 305, "#10B981", 70, "VHOST", 0.06, -0.06, "left"),
        (0.24, 342, "#38BDF8", 60, "STAGE 1-3", 0.07, -0.02, "left"),
    ]

    for rad, deg, col, sz, lbl, dx, dy, ha in nodes:
        ang = math.radians(deg)
        x = rad * math.cos(ang)
        y = rad * math.sin(ang)
        ax.plot([0, x], [0, y], color=col, linewidth=0.9, alpha=0.35, zorder=4)
        ax.scatter([x], [y], s=sz * 2.6, color=col, alpha=0.16, edgecolors="none", zorder=5)
        ax.scatter([x], [y], s=sz, color=col, edgecolors="#121316", linewidths=1.2, zorder=6)
        ax.text(
            x + dx,
            y + dy,
            lbl,
            color="#E2E8F0",
            fontsize=8.2,
            fontfamily="Consolas",
            fontweight="bold",
            ha=ha,
            va="center",
            bbox=dict(boxstyle="square,pad=0.22", facecolor="#121316", edgecolor="#262A33", linewidth=0.7, alpha=0.92),
            zorder=7,
        )

    # Center core hexagon + reticle
    core = RegularPolygon((0, 0), numVertices=6, radius=0.11, orientation=0, facecolor="#1B1D22", edgecolor="#F98406", linewidth=2.0, zorder=8)
    ax.add_patch(core)
    ax.scatter([0], [0], s=42, color="#F98406", zorder=9)
    ax.text(
        0,
        -0.16,
        "ASI CORE",
        color="#F98406",
        fontsize=8.5,
        fontfamily="Consolas",
        fontweight="bold",
        ha="center",
        va="top",
        bbox=dict(boxstyle="square,pad=0.18", facecolor="#121316", edgecolor="none", alpha=0.88),
        zorder=9,
    )

    # Corner scope brackets
    b = 1.15
    blen = 0.13
    for sx, sy in [(-1, 1), (1, 1), (1, -1), (-1, -1)]:
        ax.plot([sx * b, sx * (b - blen)], [sy * b, sy * b], color="#F98406", linewidth=2.0, alpha=0.75)
        ax.plot([sx * b, sx * b], [sy * b, sy * (b - blen)], color="#F98406", linewidth=2.0, alpha=0.75)

    dst = OUT_DIR / "cover_radar.png"
    fig.savefig(dst, dpi=240, bbox_inches="tight", pad_inches=0.04, facecolor="#121316")
    plt.close(fig)
    print(f"Prepared {dst.name}")


if __name__ == "__main__":
    prepare_screenshots()
    render_asi_logo()
    render_cover_radar()
