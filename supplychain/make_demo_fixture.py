"""Write a malicious pickle for demonstrating the scanner.

Creating the file is harmless: the payload only runs if something unpickles
it, and nothing in this repository ever does. The file is generated on demand
and never committed.

  python supplychain/make_demo_fixture.py /tmp/demo
"""
import os
import pathlib
import pickle
import sys


class _Payload:
    def __reduce__(self):
        return (os.system, ("echo innovabank-demo: code ran at model load",))


def main() -> int:
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "demo-artifacts")
    out.mkdir(parents=True, exist_ok=True)
    target = out / "pytorch_model.bin"
    target.write_bytes(pickle.dumps({"weights": [0.1, 0.2], "hook": _Payload()}))
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
