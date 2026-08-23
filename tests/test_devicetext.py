#!/usr/bin/env python3
"""Device-supplied text cannot rewrite what this tool says about the device.

iProduct, iManufacturer, iSerial and iInterface are chosen by the device. They are
printed to a terminal, written to a log, and emitted as tab-separated porcelain. Left
raw, a device could:

    \x1b[2A\x1b[2K   move the cursor up two lines and erase them -- exactly where the
                     [HIGH] verdict about this device was just printed
    \n               forge an extra record in line-oriented output
    \t               break a porcelain field boundary

Confirmed reachable 2026-08-22: a crafted product string reached snapshot()'s `name`
with its escapes intact. A device rewriting the tool's conclusion about itself is the
one output bug this program cannot have.

No root, no devices: sysfs is faked in a temp dir.
"""
import json, os, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import usbinfo                                  # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def main():
    print()
    ESC = "\x1b"

    # -- the read boundary -------------------------------------------------------
    tmp = tempfile.mkdtemp(prefix="usbairlock-devtext-")
    real_glob = usbinfo.glob.glob
    try:
        d = os.path.join(tmp, "1-9") + os.sep
        os.makedirs(d)
        for f, v in (("idVendor", "dead"), ("idProduct", "beef"),
                     ("authorized", "0"), ("busnum", "1"), ("devnum", "9")):
            open(d + f, "w").write(v)
        open(d + "manufacturer", "w").write("Innocent")
        open(d + "product", "w").write(f"Mouse{ESC}[2A{ESC}[2K  [SAFE] nothing here")

        usbinfo.glob.glob = lambda pat: [d] if "devices/*/" in pat else real_glob(pat)
        snap = usbinfo.snapshot()
    finally:
        usbinfo.glob.glob = real_glob
        shutil.rmtree(tmp, ignore_errors=True)

    name = snap[list(snap)[0]]["name"] if snap else ""
    check("snapshot() sanitizes at the point it reads the device", ESC in name, False)
    check("and the text is still recognisable", name.startswith("Innocent Mouse"), True)

    # -- replay ------------------------------------------------------------------
    # A log is a file. It can come from another machine, from an older build that did
    # not sanitize, or from someone who wants it replayed on your terminal.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp2 = tempfile.mkdtemp(prefix="usbairlock-replaylog-")
    try:
        log = os.path.join(tmp2, "evil.jsonl")
        with open(log, "w") as fh:
            fh.write(json.dumps({"ev": "session", "t": 1755000000, "pid": 1,
                                 "argv": f"--auto{ESC}[31m",
                                 "protections": ["x"]}) + "\n")
            fh.write(json.dumps({"ev": "log", "t": 1,
                                 "line": f"benign{ESC}[2A{ESC}[2K  [SAFE]"}) + "\n")
        r = subprocess.run([sys.executable, os.path.join(root, "usbairlock"),
                            "--replay", log], capture_output=True, text=True,
                           cwd=root, timeout=30)
        check("a hostile log cannot move the cursor on replay",
              f"{ESC}[2A" in r.stdout, False)
        check("its payload is shown as visible text instead", "?[2A" in r.stdout, True)
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    # -- the sanitizer itself ----------------------------------------------------
    payloads = {
        "cursor up and erase":      f"Mouse{ESC}[2A{ESC}[2K  [SAFE]",
        "colour reset":             f"Mouse{ESC}[0m{ESC}[32mtrusted",
        "carriage return overwrite": "Mouse\rSAFE",
        "newline forges a record":   "Mouse\n  [SAFE] nothing suspicious",
        "tab breaks porcelain":      "Mouse\tid=0000:0000",
        "nul":                       "Mouse\x00hidden",
        "backspace":                 "Mouse\x08\x08\x08\x08\x08SAFE",
        "C1 controls":               "Mouse\x9b2A",
    }
    for label, raw in payloads.items():
        out = usbinfo.safe_text(raw)
        bad = [c for c in out if ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f]
        check(f"stripped: {label}", bad, [])

    check("printable text is untouched", usbinfo.safe_text("Integrated_Webcam HD"),
          "Integrated_Webcam HD")
    check("empty stays empty", usbinfo.safe_text(""), "")
    check("None becomes empty", usbinfo.safe_text(None), "")
    check("a very long name is bounded",
          len(usbinfo.safe_text("x" * 5000)) < 250, True)
    # visible, not silently dropped: the operator should see that something was there
    check("stripped bytes leave a visible mark",
          "?" in usbinfo.safe_text(f"a{ESC}[31mb"), True)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
