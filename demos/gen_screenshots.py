#!/usr/bin/env python3
"""Generate SVG screenshots for shohei demos using the `rich` library."""

import subprocess
import sys
from pathlib import Path

BINARY = Path(__file__).parent.parent / "target" / "release" / "shohei"
IMAGES = Path(__file__).parent.parent / "images"

try:
    from rich.console import Console
    from rich.text import Text
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "rich"], check=True)
    from rich.console import Console
    from rich.text import Text

ENV = {
    "FORCE_COLOR": "1",
    "TERM": "xterm-256color",
    "NO_COLOR": "",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
}


def capture(args: list[str], width: int = 110) -> str:
    result = subprocess.run(
        [str(BINARY)] + args,
        capture_output=True,
        text=True,
        env=ENV,
        timeout=30,
    )
    return result.stdout + result.stderr


def save_svg(output: str, filename: str, title: str, width: int = 110) -> None:
    console = Console(record=True, force_terminal=True, width=width)
    console.print(Text.from_ansi(output))
    svg = console.export_svg(title=title)
    path = IMAGES / filename
    path.write_text(svg)
    print(f"  wrote {path.name} ({len(svg)//1024}KB)")


DEMOS = [
    {
        "filename": "demo_basic.svg",
        "title": "shohei — basic DNS query",
        "args": ["google.com"],
        "width": 110,
    },
    {
        "filename": "demo_mx.svg",
        "title": "shohei — MX records",
        "args": ["gmail.com", "--type", "mx"],
        "width": 110,
    },
    {
        "filename": "demo_caa.svg",
        "title": "shohei — CAA records",
        "args": ["google.com", "--type", "caa"],
        "width": 110,
    },
    {
        "filename": "demo_dnssec.svg",
        "title": "shohei — DNSSEC chain of trust",
        "args": ["cloudflare.com", "--dnssec"],
        "width": 110,
    },
    {
        "filename": "demo_trace.svg",
        "title": "shohei — iterative resolution trace",
        "args": ["google.com", "--trace"],
        "width": 120,
    },
    {
        "filename": "demo_authority.svg",
        "title": "shohei — authority and additional sections",
        "args": ["google.com", "--server", "192.5.6.30", "--no-recurse"],
        "width": 110,
    },
    {
        "filename": "demo_short.svg",
        "title": "shohei — short output",
        "args": ["gmail.com", "--type", "mx", "--short"],
        "width": 80,
    },
    {
        "filename": "demo_compare_match.svg",
        "title": "shohei — compare (matching)",
        "args": ["cloudflare.com", "--type", "ns", "--server", "8.8.8.8", "--compare", "1.1.1.1"],
        "width": 120,
    },
    {
        "filename": "demo_compare_diff.svg",
        "title": "shohei — compare (diverging)",
        "args": ["google.com", "--server", "8.8.8.8", "--compare", "1.1.1.1"],
        "width": 120,
    },
    {
        "filename": "demo_axfr.svg",
        "title": "shohei — AXFR zone transfer",
        "args": ["zonetransfer.me", "--axfr", "--server", "81.4.108.41", "--short"],
        "width": 110,
    },
]


def main() -> None:
    if not BINARY.exists():
        print(f"Error: binary not found at {BINARY}", file=sys.stderr)
        sys.exit(1)

    IMAGES.mkdir(exist_ok=True)

    targets = sys.argv[1:] if len(sys.argv) > 1 else [d["filename"] for d in DEMOS]

    for demo in DEMOS:
        if demo["filename"] not in targets and demo["filename"].removesuffix(".svg") not in targets:
            continue
        print(f"Generating {demo['filename']} ...")
        try:
            output = capture(demo["args"], demo.get("width", 110))
            if not output.strip():
                print(f"  WARNING: empty output for {demo['filename']}")
                continue
            save_svg(output, demo["filename"], demo["title"], demo.get("width", 110))
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT for {demo['filename']}")
        except Exception as e:
            print(f"  ERROR for {demo['filename']}: {e}")


if __name__ == "__main__":
    main()
