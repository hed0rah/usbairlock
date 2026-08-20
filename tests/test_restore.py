#!/usr/bin/env python3
"""What exit puts back. No root, no devices: the sysfs calls are stubbed.

These exist because of a real lockout. Restoring the root hub gate does not revive a
device that enumerated while the gate was down, because the kernel copies
authorized_default into a device's `authorized` once, at enumeration time. Plug a
keyboard in mid-session, exit cleanly, and the keyboard stayed dead until it was
physically replugged. The tool had shipped that.
"""
import os, shutil, sys, tempfile

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
    _real_authorize = protect.authorize
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

    # -- authorize() actually honours path ---------------------------------------
    # The tests above stub authorize, which is why they did not catch this: the real
    # function accepted path= and ignored it, so restore_all(path=X) fell through to
    # globbing the whole bus and switched every device on. A stub verifies the call,
    # never the behaviour. This drives the real function against a fake sysfs tree.
    protect.authorize = _real_authorize
    tmp = tempfile.mkdtemp(prefix="usbairlock-restore-")
    try:
        made = []
        for name, vid in (("1-2", "303a"), ("1-9", "dead")):
            d = os.path.join(tmp, name)
            os.makedirs(d)
            open(os.path.join(d, "idVendor"), "w").write(vid)
            open(os.path.join(d, "idProduct"), "w").write("0001")
            open(os.path.join(d, "authorized"), "w").write("0")
            made.append(d)
        target, bystander = made
        got = protect.authorize(path=target)

        def auth_of(d):
            return open(os.path.join(d, "authorized")).read().strip()

        check("authorize(path=) returns just that device", got, ["1-2"])
        check("authorize(path=) switches the target on", auth_of(target), "1")
        check("authorize(path=) leaves every other device alone", auth_of(bystander), "0")
        check("a path that is not a device authorizes nothing",
              protect.authorize(path=os.path.join(tmp, "nope")), [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
