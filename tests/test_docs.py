"""The README stays renderable and honest about its own structure."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_no_em_or_en_dashes():
    assert "—" not in README and "–" not in README


def test_generated_result_blocks_are_still_marked():
    for block in ("OFFLINE-RESULTS", "LIVE-RESULTS"):
        assert README.count(f"<!-- IB:{block}:START -->") == 1 and README.count(f"<!-- IB:{block}:END -->") == 1


def test_every_relative_link_and_image_exists():
    targets = re.findall(r"\]\(((?!https?://|#)[^)\s]+)\)", README)
    missing = [t for t in targets if not (ROOT / t.split("#")[0]).exists()]
    assert targets and missing == []


def test_architecture_diagram_is_mermaid():
    assert "```mermaid\nflowchart" in README
