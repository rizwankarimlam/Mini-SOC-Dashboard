"""Write the sample logs to the sample_logs/ folder:  python generate_logs.py"""
from pathlib import Path

from soc.generator import generate

out = Path(__file__).parent / "sample_logs"
out.mkdir(exist_ok=True)
for name, text in generate().items():
    (out / name).write_text(text, encoding="utf-8")
    print(f"wrote {out / name} ({len(text.splitlines())} lines)")
