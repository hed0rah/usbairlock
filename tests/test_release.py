#!/usr/bin/env python3
"""Allowing a device mid-session must RELEASE it, not just exempt a future replug.

Found on hardware 2026-08-22: `--authorize` on a keyboard that was being captured
printed "+ allowed" and the keyboard stayed dead. The allow handler set SKIP so a
replug would not be withheld, but a live capture holds the interface through usbfs
and keeps usbhid detached, so the device was admitted on paper and unusable in fact.

No root, no devices. The capture threads are stubbed; what is under test is the
bookkeeping that decides which capture to stop.
"""
import os, sys, threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import capture as capmod                        # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def load_drop():
    """_drop_capture out of the main script, which is not importable as a module."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "usbairlock")).read()
    start = src.index("def _drop_capture(")
    end = src.index("def _start_capture(")
    ns = {}
    exec(compile(src[start:end], "<drop>", "exec"), ns)
    return ns["_drop_capture"]


def main():
    print()
    _drop_capture = load_drop()

    def entry(vp):
        return (object(), threading.Event(), vp)

    # -- the shape that shipped broken -------------------------------------------
    # keyed by ADDRESS, reported by vid:pid. popping by vid:pid missed entirely.
    caps = {"1-1": entry("1a2c:2d23"), "4-1": entry("090c:1000")}
    dropped = _drop_capture(caps, "1a2c:2d23", release=True)
    check("a capture keyed by address is found by its vid:pid", dropped, ["1-1"])
    check("and is removed from the dict", sorted(caps), ["4-1"])

    caps2 = {"1-1": entry("1a2c:2d23"), "4-1": entry("090c:1000")}
    ev_target = caps2["1-1"][1]
    ev_other = caps2["4-1"][1]
    _drop_capture(caps2, "1a2c:2d23", release=True)
    check("the released capture is told to stop", ev_target.is_set(), True)
    check("every OTHER capture keeps running", ev_other.is_set(), False)

    # -- cleanup path must not stop anything, the thread is already gone ---------
    caps3 = {"1-1": entry("1a2c:2d23")}
    ev3 = caps3["1-1"][1]
    _drop_capture(caps3, "1a2c:2d23")
    check("an unplug drops the entry", caps3, {})
    check("without setting a stop event nobody is waiting on", ev3.is_set(), False)

    # -- the fallback keying, when no address resolved ---------------------------
    caps4 = {"1a2c:2d23": entry("1a2c:2d23")}
    check("a capture keyed by vid:pid is also found",
          _drop_capture(caps4, "1a2c:2d23"), ["1a2c:2d23"])

    check("dropping something absent is not an error",
          _drop_capture({}, "dead:beef"), [])

    # two identical devices, one allowed: the other must keep being watched
    caps5 = {"1-1": entry("1a2c:2d23"), "1-2": entry("1a2c:2d23"),
             "4-1": entry("090c:1000")}
    check("identical twins both release together",
          sorted(_drop_capture(caps5, "1a2c:2d23", release=True)), ["1-1", "1-2"])
    check("and the unrelated device is untouched", sorted(caps5), ["4-1"])

    # -- restore() now runs on release AND from the exit cleanup -----------------
    # Both paths call it, so a second run must be a no-op. Proven behaviourally:
    # make what it restores unwritable, then a second run that actually executed
    # would print "capture restore failed" for a device it had already restored fine.
    import contextlib, io, shutil, tempfile
    tmp = tempfile.mkdtemp(prefix="usbairlock-release-")
    real_dev_dir = capmod.dev_dir
    try:
        dev = os.path.join(tmp, "1-1") + os.sep
        os.makedirs(os.path.join(dev, "1-1:1.0"))
        open(os.path.join(dev, "idVendor"), "w").write("1a2c")
        open(os.path.join(dev, "idProduct"), "w").write("2d23")
        open(os.path.join(dev, "authorized"), "w").write("0")
        open(os.path.join(dev, "1-1:1.0", "authorized"), "w").write("0")
        capmod.dev_dir = lambda vp: dev

        steps, restore = capmod.prepare("1a2c:2d23", 0)
        check("prepare lifts the device gate so there are interfaces to read",
              any("device gate lifted" in s_ for s_ in steps), True)
        check("and makes the interface claimable", any("1-1:1.0" in s_ for s_ in steps), True)
        # The kernel spells device-scope and interface-scope authorization identically
        # and this tool spells its allow list that way too, so one log line carried
        # three meanings and read like the gate had failed. Do not reuse the word.
        check("without reusing the word 'authorized' for it",
              any("authorized 1-1:1.0" in s_ for s_ in steps), False)
        check("and it says the driver gate is still shut",
              any("driver gate stays shut" in s_ or "no driver can bind" in s_
                  for s_ in steps), True)

        for f in ("authorized", os.path.join("1-1:1.0", "authorized")):
            os.chmod(os.path.join(dev, f), 0o444)
        first, second = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(first): restore()
        with contextlib.redirect_stdout(second): restore()
        check("the first restore really does try to put things back",
              "capture restore failed" in first.getvalue(), True)
        check("and a genuine failure is still reported, not swallowed",
              "Permission denied" in first.getvalue(), True)
        check("the second is a no-op, not a second attempt", second.getvalue(), "")
    finally:
        capmod.dev_dir = real_dev_dir
        for root, dirs, files in os.walk(tmp):
            for f_ in files:
                try: os.chmod(os.path.join(root, f_), 0o644)
                except OSError: pass
        shutil.rmtree(tmp, ignore_errors=True)

    # -- should_stop is honoured by both capture entry points --------------------
    import inspect
    check("capture() takes should_stop",
          "should_stop" in inspect.signature(capmod.capture).parameters, True)
    check("capture_forever() takes should_stop",
          "should_stop" in inspect.signature(capmod.capture_forever).parameters, True)

    # a capture_forever told to stop before it starts must not prepare() anything
    prepared = []
    real_prep = capmod.prepare
    try:
        capmod.prepare = lambda *a, **k: (prepared.append(1), (["x"], lambda: None))[1]
        list(capmod.capture_forever("dead:beef", 0, 0x81, should_stop=lambda: True))
    finally:
        capmod.prepare = real_prep
    check("a stop before the first read detaches nothing", prepared, [])

    # -- chord labels ------------------------------------------------------------
    # Seen on hardware 2026-08-22: three "ALT+" lines with nothing after the plus.
    # It was ALT+TAB. ENTER, TAB and space are whitespace in the typed text, which is
    # right for reading prose, but ch.strip() erased them inside a chord and threw away
    # the single most interesting thing a hostile keyboard can do.
    def chord(mod, key):
        return capmod.decode(bytes([mod, 0, key, 0, 0, 0, 0, 0]), set())[1]

    check("ALT+TAB is named, not blank", chord(0x04, 43), ["ALT+TAB"])
    check("ALT+SPACE is named", chord(0x04, 44), ["ALT+SPACE"])
    check("ALT+ENTER is named", chord(0x04, 40), ["ALT+ENTER"])
    check("a printable chord is unchanged", chord(0x01, 6), ["CTRL+c"])
    check("several modifiers sort deterministically", chord(0x05, 76), ["ALT+CTRL+<DEL>"])
    check("shift alone is not a chord, it is capitalisation", chord(0x02, 4), [])
    check("and shift alone still produces the letter",
          capmod.decode(bytes([0x02, 0, 4, 0, 0, 0, 0, 0]), set())[0], "A")

    # -- an allowed device must END UP authorized -------------------------------
    # Two ways it did not, both found on hardware 2026-08-22 and both fixed by stating
    # the invariant instead of ordering the events:
    #   1. releasing a capture runs prepare()'s restore(), which puts back the values
    #      recorded BEFORE it authorized anything. --authorize granted trust and the
    #      release revoked it a moment later.
    #   2. SKIP only spares a device from being unbound. It does nothing about the root
    #      hub gate, so an allowed device that gets replugged enumerates unauthorized
    #      and "on the allow list, left alone" left it dead.
    from airlock import protect as protmod
    import shutil, tempfile
    tmp2 = tempfile.mkdtemp(prefix="usbairlock-reconcile-")
    try:
        made = {}
        for name, vid, auth in (("1-1", "1a2c", "0"),    # allowed but withheld
                                ("1-2", "303a", "0"),    # not allowed, stays withheld
                                ("1-5", "0bda", "1")):   # already fine
            d_ = os.path.join(tmp2, name)
            os.makedirs(d_)
            open(os.path.join(d_, "idVendor"), "w").write(vid)
            open(os.path.join(d_, "idProduct"), "w").write("0001")
            open(os.path.join(d_, "authorized"), "w").write(auth)
            made[name] = d_

        def auth_of(n):
            return open(os.path.join(made[n], "authorized")).read().strip()

        # the reconciler in one line, exactly as the monitor runs it
        allow = {"1a2c:0001"}
        snap = {"a": {"id": "1a2c:0001", "authorized": "0", "sysfs": made["1-1"] + os.sep},
                "b": {"id": "303a:0001", "authorized": "0", "sysfs": made["1-2"] + os.sep},
                "c": {"id": "0bda:0001", "authorized": "1", "sysfs": made["1-5"] + os.sep}}
        for _k, m_ in sorted(snap.items()):
            if m_["id"] in allow and m_.get("authorized") == "0":
                protmod.authorize(path=m_.get("sysfs"))

        check("an allowed but withheld device gets authorized", auth_of("1-1"), "1")
        check("a device NOT on the allow list stays withheld", auth_of("1-2"), "0")
        check("an already authorized device is untouched", auth_of("1-5"), "1")

        # idempotent: the loop runs every tick and must not thrash
        before = auth_of("1-1")
        for _k, m_ in sorted(snap.items()):
            if m_["id"] in allow and m_.get("authorized") == "0":
                protmod.authorize(path=m_.get("sysfs"))
        check("running the reconciler again changes nothing", auth_of("1-1"), before)
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    # -- protection coverage -----------------------------------------------------
    # Found on hardware 2026-08-22: an ESP32-C3 already attached when the monitor
    # started kept cdc_acm bound and /dev/ttyACM0 live, while an already-attached
    # keyboard was stripped by unbind_hid. Same situation, opposite treatment, only
    # because no protection covered CDC.
    from airlock import protect as protmod2
    check("there is a serial protection at all",
          "unbind_serial" in protmod2.REGISTRY, True)
    check("--paranoid turns it on, because it turns on everything in the registry",
          all(k in protmod2.REGISTRY for k in
              ("unbind_hid", "unbind_storage", "unbind_net", "unbind_serial")), True)

    # cdc_acm is the one that actually bit. option is the one that matters most: it
    # binds cellular modems, which is unbind_net's DNS/routing takeover arriving over
    # a serial interface instead of an ethernet one.
    import inspect as _i
    src = _i.getsource(protmod2.unbind_serial)
    for drv in ("cdc_acm", "ftdi_sio", "ch341", "cp210x", "pl2303", "option"):
        check(f"covers {drv}", drv in src, True)

    # every registry entry must be callable and describe itself, or --status and the
    # generated --flag/--no-flag pair silently do nothing
    for name, (fn, desc) in protmod2.REGISTRY.items():
        if not (callable(fn) and isinstance(desc, str) and desc):
            check(f"{name} is wired up", False, True)
            break
    else:
        check("every protection is callable and documented", True, True)

    # -- every prepare() must be undoable, including the ones after a reconnect ---
    # capture_forever calls prepare() again each time the device re-enumerates, and the
    # reconnect branch discarded its return value: the new changes were never registered
    # for cleanup and the one registered undo still pointed at the OLD device's paths.
    # The docstring says devices held by this tool re-enumerate repeatedly, so this was
    # the common path, and "restored N kernel setting(s)" was under-reporting.
    prepared_calls, undone = [], []
    real_prepare, real_find = capmod.prepare, capmod.find_node
    real_capture = capmod.capture

    class _Boom(Exception):
        pass

    try:
        def fake_prepare(vp, iface=0):
            n = len(prepared_calls)
            prepared_calls.append(n)
            return ([f"prepared #{n}"], lambda n=n: undone.append(n))

        # first capture() raises _Reconnect, second stops immediately
        calls = {"n": 0}
        def fake_capture(vp, iface=0, ep=0x81, on_event=None, on_lost=None,
                         seconds=None, should_stop=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise capmod._Reconnect()
            return iter(())

        capmod.prepare = fake_prepare
        capmod.find_node = lambda vp: "/dev/bus/usb/001/002"
        capmod.capture = fake_capture

        stop = {"go": False}
        gen = capmod.capture_forever("dead:beef", 0, 0x81,
                                     should_stop=lambda: stop["go"])
        list(gen)                       # runs through the reconnect and returns
        check("prepare ran again after the re-enumeration", len(prepared_calls), 2)

        # Now stop it the moment the reconnect has re-prepared, and confirm BOTH
        # prepares get undone. should_stop is polled at the top of the loop, so asking
        # it to go true once prepare has run twice lands exactly after the reconnect.
        prepared_calls.clear(); undone.clear(); calls["n"] = 0
        gen2 = capmod.capture_forever("dead:beef", 0, 0x81,
                                      should_stop=lambda: len(prepared_calls) >= 2)
        list(gen2)
        check("the reconnect really did prepare a second time", len(prepared_calls), 2)
        check("both prepares are undone on stop, not just the first",
              sorted(set(undone)), [0, 1])

        # and each undo registered with protect, so process exit puts them back too
        from airlock import protect as _pr
        before = len(_pr._cleanups)
        prepared_calls.clear(); undone.clear(); calls["n"] = 0
        list(capmod.capture_forever("dead:beef", 0, 0x81,
                                    should_stop=lambda: len(prepared_calls) >= 2))
        check("every prepare registers an exit cleanup, not just the first",
              len(_pr._cleanups) - before, 2)
    finally:
        capmod.prepare, capmod.find_node, capmod.capture = real_prepare, real_find, real_capture

    # A path that no longer exists is a device that left, not a failed restore. This
    # matters now that every re-enumeration registers its own undo: the old paths are
    # gone by definition once devnum changes, so reporting each as a failure would bury
    # a real one in noise that is guaranteed to happen.
    import contextlib as _c, io as _io, shutil as _sh, tempfile as _tf
    tmp3 = _tf.mkdtemp(prefix="usbairlock-vanish-")
    real_dd = capmod.dev_dir
    try:
        dev3 = os.path.join(tmp3, "1-1") + os.sep
        os.makedirs(os.path.join(dev3, "1-1:1.0"))
        for f_, v_ in (("idVendor", "1a2c"), ("idProduct", "2d23"), ("authorized", "0")):
            open(os.path.join(dev3, f_), "w").write(v_)
        open(os.path.join(dev3, "1-1:1.0", "authorized"), "w").write("0")
        capmod.dev_dir = lambda vp: dev3
        _steps3, restore3 = capmod.prepare("1a2c:2d23", 0)
    finally:
        capmod.dev_dir = real_dd
    _sh.rmtree(tmp3, ignore_errors=True)          # the device leaves
    out3 = _io.StringIO()
    with _c.redirect_stdout(out3):
        restore3()
    check("a device that vanished restores silently, it did not fail",
          out3.getvalue(), "")

    # -- the bind race -----------------------------------------------------------
    # Observed on hardware 2026-08-22: a key held down across a re-enumeration produced
    # a character in the operator's terminal, from a keyboard being deliberately held.
    # prepare() authorized the interface and detached usbhid AFTERWARDS, with a comment
    # admitting "authorizing may have let usbhid bind". It had. Suspending bus-wide
    # auto-binding first removes the window rather than shortening it.
    src_prep = _i.getsource(capmod.prepare)
    ap_at = src_prep.find("AUTOPROBE")
    auth_at = src_prep.find('_w(dev+"authorized", 1)')
    check("prepare suspends driver auto-binding", ap_at != -1, True)
    check("and does it BEFORE authorizing anything",
          ap_at != -1 and auth_at != -1 and ap_at < auth_at, True)
    check("the switch is restored inside prepare, not held for the whole session",
          src_prep.count("_autoprobe_restore()") >= 1, True)
    check("and registered with protect so a crash cannot leave the bus unable to bind",
          "add_cleanup(_autoprobe_restore)" in src_prep, True)
    check("the constant points at the real sysfs switch",
          capmod.AUTOPROBE, "/sys/bus/usb/drivers_autoprobe")

    # -- arrival/departure ordering ----------------------------------------------
    # `seen` is keyed by bus/dev, so a device that re-enumerates inside one poll is a
    # vanished key plus a new one. Arrivals-first reported the new devnum before the old
    # one left -- "arrived, arrived, removed" for one device that had reset -- and the
    # arrival branch saw its own address still in `capturing`, skipped starting a
    # capture, then the departure branch dropped the entry: device present, nothing
    # capturing it. Seen on a dock, 2026-08-22.
    mon = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "usbairlock")).read()
    dep_at = mon.find("for k in sorted(set(seen) - set(now)):")
    arr_at = mon.find("for k in sorted(set(now) - set(seen)):")
    check("departures are processed before arrivals",
          dep_at != -1 and arr_at != -1 and dep_at < arr_at, True)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
