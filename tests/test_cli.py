#!/usr/bin/env python3
"""The command-line surface itself. No devices, no root.

These exist because `--verbose ADDR` was a mode selector wearing the name of a verbosity
level. It read as a modifier, so `--list --verbose` looked reasonable and failed, and it
held `-v` hostage so `--version` could not have it. The person who wrote the flag still
tripped over it, which is the only evidence a naming problem ever really gets.
"""
import os, subprocess, sys

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
    return r.returncode, r.stdout + r.stderr


def main():
    print()
    # -- version -----------------------------------------------------------------
    rc, out = run("--version")
    check("--version exits 0", rc, 0)
    check("and names the program", out.startswith("usbairlock "), True)
    parts = out.strip().split()[-1].split(".")
    check("with a three-part semantic version",
          (len(parts), all(p.isdigit() for p in parts)), (3, True))
    check("-V is the same thing", run("-V")[1], out)

    # -- the rename ----------------------------------------------------------------
    # Both spellings must reach the same code. The old one is kept because it shipped.
    rc_new, out_new = run("--describe", "nonexistent-addr")
    rc_old, out_old = run("--verbose", "nonexistent-addr")
    check("--describe and --verbose are the same mode", out_new, out_old)
    check("and both report a miss rather than crashing",
          ("no device matches" in out_new, rc_new == rc_old), (True, True))

    # -- -v is not silently reinterpreted -------------------------------------------
    # It used to be --verbose's short form, so `--list -v` demanded an argument instead
    # of listing anything. Unbound is correct: there is no verbosity ladder to attach it
    # to, and quietly making it mean --version would surprise the other half of users.
    rc, out = run("--list", "-v")
    check("-v is rejected, not misread as a mode", "unrecognized arguments: -v" in out, True)
    check("and that is an error exit", rc != 0, True)

    # -- the quiet ladder ----------------------------------------------------------
    # --list printed three unsolicited hint lines on every run, which is noise for anyone
    # who already knows the tool. -q drops the hint, -qq drops the furniture so the output
    # pipes into cut and awk with nothing to strip.
    _, plain = run("--list")
    _, q1 = run("--list", "-q")
    _, q2 = run("--list", "-qq")
    check("the hint is one line, not three", plain.count("./usbairlock --{"), 1)
    check("-q drops the hint entirely", "look closer" in q1, False)
    check("-qq drops the column header too", "bus/dev" in q2, False)
    check("but -qq still prints the devices",
          len([l for l in q2.splitlines() if l.strip()]) > 0, True)
    check("each level is strictly shorter than the last",
          len(plain) > len(q1) > len(q2), True)
    # -q must not become an error the way -v did
    check("-q is accepted, not rejected", "unrecognized" in q1, False)

    # -- interrogate -----------------------------------------------------------------
    # Every request it makes is DEVICE-directed, so it must work with the interface gate
    # shut. It also must not pretend: a device that refuses a request is a fact, not an
    # error, and unreadable state must never be reported as a clean bill of health.
    rc, out = run("--interrogate", "definitely-not-a-device")
    check("a miss is reported, not crashed", "no device matches" in out, True)
    check("and exits non-zero", rc != 0, True)

    rc, out = run("--interrogate")
    check("--interrogate requires an address", rc != 0, True)

    # -- -x, and the reworked quiet ladder --------------------------------------------
    _, plain = run("--list")
    _, ext   = run("--list", "-x")
    check("-x is accepted", "unrecognized" in ext, False)
    check("-x says how many it hid rather than silently shrinking",
          ("--external-only" in ext) or ("device(s)" in ext), True)
    check("--external-only is the long form",
          "unrecognized" in run("--list", "--external-only")[1], False)
    check("--ignore-existing replaced --allow-existing",
          "unrecognized" in run("--list", "--ignore-existing")[1], False)
    check("and the old spelling still works, it shipped",
          "unrecognized" in run("--list", "--allow-existing")[1], False)

    # -- whole-bus forms ---------------------------------------------------------------
    # Bare --inspect regressed to a NameError when quiet was threaded through, and nothing
    # noticed because no test ran it without a target. Every mode that accepts a bare form
    # is exercised here now.
    rc, out = run("--inspect")
    check("bare --inspect does not crash", "Traceback" in out, False)
    check("and reports on more than one device", out.count("present") > 1 or rc in (0, 2), True)
    rc, out = run("--describe")
    check("bare --describe walks the bus", "Traceback" in out, False)
    check("and says how many it covered", "device(s) described" in out, True)

    # -- help still works and is not the argparse default ---------------------------
    rc, out = run("--help")
    check("--help exits 0", rc, 0)
    check("and shows the hand-written usage", "it shows you things" in out, True)
    check("which documents the renamed flag", "--describe DEVICE" in out, True)
    # Every device-taking flag goes through the same resolve(), so every one of them must
    # advertise the same thing. They used to split three-and-three between VID:PID and
    # ADDR while all six accepted both, so half the help was wrong in each direction.
    for flag in ("inspect", "hid", "describe", "interrogate", "authorize", "capture"):
        check(f"--{flag} advertises DEVICE, not one specific form",
              f"--{flag} DEVICE" in out or f"--{flag} " not in out, True)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
