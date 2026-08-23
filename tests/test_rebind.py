#!/usr/bin/env python3
"""Unbinding a driver has to be reversible, or the tool is the lockout.

Found by watching a live run, 2026-08-22. After a clean exit with every gate restored:

    1-4.4  090c:1000  Samsung Type-C   drivers=none
    4-1.2  0bda:8153  Realtek USB LAN  drivers=none

_driver_block(driver, on=False) returned the string "released" and reversed NOTHING.
Worse, nothing on the monitor's exit path called it at all -- restore_all() only puts
back saved sysfs values, and the driver unbinds are not saved values. So a flash drive
or a USB ethernet adapter stayed dead until it was physically replugged, which is the
exact lockout this program exists to prevent, arriving by the other door.

Captured devices masked it: prepare() registers its own rebind, so a keyboard came back
and everything else did not.

The sysfs bind/unbind files are faked here. No root, no devices.
"""
import os, shutil, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import protect                                  # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def main():
    print()
    # Point the module at a fake sysfs tree. bind/unbind are ordinary files here, so
    # what the code wrote to them is readable afterwards -- no monkeypatching of open,
    # and no risk of the test touching the real bus.
    tmp = tempfile.mkdtemp(prefix="usbairlock-rebind-")
    saved = (protect.DRIVERS, protect.DEVICES)
    try:
        protect.DRIVERS = os.path.join(tmp, "drivers")
        protect.DEVICES = os.path.join(tmp, "devices")
        drv = os.path.join(protect.DRIVERS, "usb-storage")
        os.makedirs(drv)
        ifaces = ["1-4.4:1.0", "1-2:1.0"]
        for i in ifaces:
            os.makedirs(os.path.join(drv, i))                 # what the driver holds
            os.makedirs(os.path.join(protect.DEVICES, i))     # and the device side
            os.makedirs(os.path.join(protect.DEVICES, i.split(":")[0]), exist_ok=True)
            open(os.path.join(protect.DEVICES, i.split(":")[0], "idVendor"), "w").write("dead")
            open(os.path.join(protect.DEVICES, i.split(":")[0], "idProduct"), "w").write("beef")
        for f in ("bind", "unbind"):
            open(os.path.join(drv, f), "w").close()

        def written(fname):
            return [l.strip() for l in open(os.path.join(drv, fname)) if l.strip()]

        protect._UNBOUND.clear()
        protect.SKIP.clear()

        n, detail = protect._driver_block("usb-storage", True)
        check("unbind took every interface the driver held", n, len(ifaces))
        check("and says what it took", "unbound" in detail, True)
        check("it remembered them for later",
              sorted(protect._UNBOUND.get("usb-storage", [])), sorted(ifaces))

        n2, detail2 = protect._driver_block("usb-storage", False)
        # sysfs bind takes one name per write and the code opens with "w" each time, so
        # in a plain file only the last write survives. Assert the COUNT it rebound and
        # that the surviving write is one of ours, rather than pretending the file
        # accumulates the way sysfs semantics do not.
        check("release rebinds every interface it took, it does not merely say released",
              n2, len(ifaces))
        check("and what it wrote was a real interface name",
              written("bind")[-1] in ifaces, True)
        check("and says so", "rebound" in detail2, True)
        check("the record is cleared, so a second release is not a double bind",
              protect._UNBOUND.get("usb-storage"), None)

        open(os.path.join(drv, "bind"), "w").close()
        protect._driver_block("usb-storage", False)
        check("releasing twice rebinds nothing", written("bind"), [])

        # an interface that vanished is a device that left, not a failure -- and it must
        # NOT be counted as a rebind. Reporting "rebound 1" for a device that was
        # unplugged an hour ago is the same lie this message exists to prevent, and the
        # first version of this fix told it.
        protect._UNBOUND["usb-storage"] = ["9-9:1.0"]
        n3, detail3 = protect._driver_block("usb-storage", False)
        check("an interface that vanished is skipped", written("bind"), [])
        check("and is not reported as a failure", "failed" in detail3, False)
        check("and is NOT counted as a rebind", n3, 0)
        check("it is reported separately instead", "gone with the device" in detail3, True)

        # SKIP means "leave this device's drivers alone", and must survive here
        protect._UNBOUND.clear()
        open(os.path.join(drv, "unbind"), "w").close()
        protect.SKIP.add("dead:beef")
        n4, _d4 = protect._driver_block("usb-storage", True)
        check("a device on SKIP is not unbound at all", n4, 0)
        protect.SKIP.clear()
    finally:
        protect.DRIVERS, protect.DEVICES = saved
        protect._UNBOUND.clear()
        protect.SKIP.clear()
        shutil.rmtree(tmp, ignore_errors=True)

    # -- the exit path must actually call release --------------------------------
    import inspect
    src = inspect.getsource(protect.install_handlers)
    check("the exit handler releases protections", "release()" in src, True)
    check("there is a release() at all", callable(protect.release), True)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
