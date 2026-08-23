#!/usr/bin/env python3
"""--porcelain is a contract: every line is a record, and records identify a device.

Both halves were broken, found 2026-08-22 with two identical CH340 boards attached:

  1. The monitor's `arrived`, `present` and `threat` records carried no `addr`, while
     --status and --inspect emitted the SAME record kinds WITH one. So the same record
     name had different fields depending on which mode produced it, and with two
     identical devices plugged in the monitor's output was byte-identical -- a consumer
     could not tell which device had arrived.
  2. Departures, serial nodes appearing and going, the --force warning, the startup
     banner and the exit line were printed as prose INTO the machine stream. Anything
     parsing it hit unparseable lines, and tracking live state from the stream drifted
     permanently after the first unplug, because devices arrived and never left.

Runs the real binary unprivileged. No devices needed.
"""
import os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "usbairlock")
G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []
RECORD = re.compile(r"^[a-z_]+(\t[a-z_]+=[^\t]*)*$")


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def run(*args):
    r = subprocess.run([sys.executable, BIN] + list(args),
                       capture_output=True, text=True, cwd=ROOT, timeout=60)
    return r.returncode, r.stdout


def bad_lines(out):
    return [l for l in out.splitlines() if l.strip() and not RECORD.match(l)]


def main():
    print()
    # every one-shot mode must emit records and nothing else
    for mode in (["--list"], ["--status"], ["--diagnose"], ["--inspect"]):
        rc, out = run(*(mode + ["--porcelain"]))
        check(f"{' '.join(mode)} emits only records", bad_lines(out), [])
        check(f"{' '.join(mode)} emits at least one", bool(out.strip()), True)

    # the observe monitor: banner, watching line and exit line all used to be prose
    tmp = tempfile.mkdtemp(prefix="usbairlock-porc-")
    env = dict(os.environ, USBAIRLOCK_RUN=os.path.join(tmp, "run"))
    # The monitor never returns on its own, so run it and take it down: subprocess.run
    # with a timeout would raise and throw away exactly the output under test.
    proc = subprocess.Popen([sys.executable, BIN, "--observe", "--porcelain",
                             "--interval", "0.3"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, cwd=ROOT, env=env)
    try:
        out_m, _ = proc.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        proc.terminate()                    # SIGTERM: the tool's own clean exit path
        try:
            out_m, _ = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            out_m, _ = proc.communicate()
    check("the monitor emits only records, banner and exit line included",
          bad_lines(out_m), [])
    check("and it produced something to check", bool(out_m.strip()), True)

    # device-identifying records must carry an address, or two identical devices are
    # indistinguishable in the exact mode where that matters
    rc, out = run("--list", "--porcelain")
    devs = [l for l in out.splitlines() if l.startswith("dev\t")]
    check("--list rows carry addr", all("\taddr=" in l for l in devs), True)

    rc, out = run("--status", "--porcelain")
    pres = [l for l in out.splitlines() if l.startswith("present\t")]
    check("--status present rows carry addr",
          all("\taddr=" in l for l in pres) if pres else True, True)

    # and the monitor's own versions of those record kinds
    src = open(BIN).read()
    for kind in ("arrived", "removed", "present", "threat"):
        m = re.search(r'porcelain\("%s",\s*addr=' % kind, src)
        check(f"monitor's {kind} record carries addr", bool(m), True)

    # a record kind must not exist in two shapes
    fields = {}
    rc, out = run("--list", "--porcelain")
    rc2, out2 = run("--status", "--porcelain")
    for line in (out + out2).splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        kind, keys = parts[0], tuple(p.split("=", 1)[0] for p in parts[1:])
        fields.setdefault(kind, set()).add(keys)
    inconsistent = {k: v for k, v in fields.items() if len(v) > 1}
    check("no record kind is emitted with two different field sets",
          sorted(inconsistent), [])

    import shutil; shutil.rmtree(tmp, ignore_errors=True)
    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
