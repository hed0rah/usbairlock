#!/usr/bin/env python3
"""What exit puts back. No root, no devices: the sysfs calls are stubbed.

These exist because of a real lockout. Restoring the root hub gate does not revive a
device that enumerated while the gate was down, because the kernel copies
authorized_default into a device's `authorized` once, at enumeration time. Plug a
keyboard in mid-session, exit cleanly, and the keyboard stayed dead until it was
physically replugged. The tool had shipped that.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import protect                                 # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def main():
    print()
    authorized = []
    protect.authorize = lambda vid_pid=None, path=None, interfaces=True: (
        authorized.append(path or vid_pid) or ["stub"])

    # -- the lockout regression --------------------------------------------------
    protect._saved.clear(); protect.WITHHELD.clear(); authorized[:] = []
    protect.note_withheld("/sys/bus/usb/devices/1-2/")
    protect.note_withheld("/sys/bus/usb/devices/1-4/")
    n = protect.restore_all()
    check("every withheld arrival is re-authorized on exit",
          sorted(authorized), ["/sys/bus/usb/devices/1-2/", "/sys/bus/usb/devices/1-4/"])
    check("and counted as restored", n, 2)
    check("the set is cleared, so a second call is not a double write",
          protect.WITHHELD, set())

    authorized[:] = []
    protect.restore_all()
    check("second restore re-authorizes nothing", authorized, [])

    # This is the specific shape that shipped broken: nothing in _saved, because the
    # gate was already down when we started, but a device still arrived under it. An
    # early `if not _saved: return 0` skipped the revival entirely.
    protect._saved.clear(); protect.WITHHELD.clear(); authorized[:] = []
    protect.note_withheld("/sys/bus/usb/devices/1-9/")
    protect.restore_all()
    check("revival happens even when no gate value needed restoring",
          authorized, ["/sys/bus/usb/devices/1-9/"])

    # -- only ours ---------------------------------------------------------------
    # A device someone else deauthorized on purpose must not be quietly switched back on.
    protect._saved.clear(); protect.WITHHELD.clear(); authorized[:] = []
    protect.restore_all()
    check("a device we never withheld is left alone", authorized, [])

    check("note_withheld ignores a missing sysfs path",
          (protect.note_withheld(None), protect.WITHHELD)[1], set())

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
