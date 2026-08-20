"""Kernel-level USB protections: apply, report, and always restore.

Everything here is reversible and records its prior value first. If this process dies,
`restore_all()` runs from an atexit hook and a signal handler, because leaving a machine
with authorized_default=0 and no way to plug a keyboard in is a worse outcome than
whatever we were defending against.
"""
import atexit, glob, os, signal, subprocess

ROOTS = "/sys/bus/usb/devices/usb*"
_saved = {}          # path -> original contents
_applied = []        # human-readable list of what is active

def _w(path, val):
    try:
        if path not in _saved:
            _saved[path] = open(path).read().strip()
        open(path, "w").write(str(val))
        return True
    except Exception:
        return False

def _read(path):
    try: return open(path).read().strip()
    except Exception: return None

def is_root(): return os.geteuid() == 0

# ---------------------------------------------------------------- protections

def withhold_device(on=True):
    """Device-level gate. A new device enumerates but NO driver binds.

    This runs before driver binding, which is the only moment the decision is still
    yours. udev cannot do this: it is userspace and fires after the kernel has already
    matched and bound a driver for many classes.
    """
    n = sum(_w(os.path.join(r, "authorized_default"), 0 if on else 1) for r in glob.glob(ROOTS))
    return n, f"device authorization withheld on {n} root hubs"

def withhold_interface(on=True):
    """Per-INTERFACE gate (kernel 4.13+). Strictly better than the device gate.

    A composite device does not have to be all-or-nothing. The device authorizes, its
    descriptors are readable, and each interface stays unbound until named. That is what
    lets you accept the CDC serial interface of a board while refusing the HID keyboard
    interface it also claims, which is the exact shape of a BadUSB serial adapter.
    """
    paths = glob.glob(os.path.join(ROOTS, "interface_authorized_default"))
    if not paths:
        return 0, "per-interface authorization not supported by this kernel (needs 4.13+)"
    n = sum(_w(p, 0 if on else 1) for p in paths)
    return n, f"interface authorization withheld on {n} root hubs"

SKIP = set()          # vid:pid values that must never be touched (the startup baseline)

def _dev_id_for_interface(iface_name):
    """1-1:1.0 -> the parent device's vid:pid"""
    parent = iface_name.split(":")[0]
    d = "/sys/bus/usb/devices/%s/" % parent
    v, p = _read(d + "idVendor"), _read(d + "idProduct")
    return "%s:%s" % (v, p) if v and p else None

def _driver_block(driver, on=True):
    """Unbind everything from a driver and stop it binding anything new.

    bind/unbind live in sysfs, so this needs no modprobe config and reverses cleanly.
    Devices in SKIP are left bound: unbinding the operator's own keyboard mid-session is
    not a protection, it is a lockout.
    """
    base = f"/sys/bus/usb/drivers/{driver}"
    if not os.path.isdir(base):
        return 0, f"{driver} not loaded, nothing to block"
    n = 0
    if on:
        for dev in glob.glob(os.path.join(base, "*:*")):
            name = os.path.basename(dev)
            if _dev_id_for_interface(name) in SKIP:
                continue
            try:
                open(os.path.join(base, "unbind"), "w").write(name); n += 1
            except Exception:
                pass
    return n, (f"{driver}: unbound {n} existing interface(s)" if on else f"{driver}: released")

def unbind_hid(on=True):
    """usbhid is what turns a claimed keyboard into keystrokes in your session."""
    return _driver_block("usbhid", on)

def unbind_storage(on=True):
    return _driver_block("usb-storage", on)

def unbind_net(on=True):
    total, msgs = 0, []
    for d in ("cdc_ether", "rndis_host", "r8152", "usbnet", "cdc_ncm"):
        n, m = _driver_block(d, on)
        total += n
        if "not loaded" not in m: msgs.append(m)
    return total, "; ".join(msgs) or "no USB network drivers loaded"

def usbfs_snoop(on=True):
    """usbfs_snoop dumps raw USB traffic to the kernel log. Very loud, very low-level."""
    p = "/sys/module/usbcore/parameters/usbfs_snoop"
    if not os.path.exists(p): return 0, "usbfs_snoop not available"
    ok = _w(p, "Y" if on else "N")
    return (1 if ok else 0), ("raw USB traffic logged to the kernel ring buffer"
                              if ok else "could not enable usbfs_snoop")

# ---------------------------------------------------------------- lifecycle

# Each protection is named for the sysfs object it writes, so the flag, the config key
# and the thing you would cat by hand all agree.
REGISTRY = {
    "withhold_interface": (withhold_interface,
        "authorized_default=0 per interface: no driver binds, descriptors stay readable"),
    "withhold_device":    (withhold_device,
        "authorized_default=0 per device: no interfaces exist at all"),
    "unbind_hid":         (unbind_hid,
        "drivers/usbhid/unbind: a claimed keyboard cannot become keystrokes"),
    "unbind_storage":     (unbind_storage,
        "drivers/usb-storage/unbind: no mass-storage autoprobe"),
    "unbind_net":         (unbind_net,
        "unbinds cdc_ether, rndis_host and friends: no DNS or route hijack"),
    "usbfs_snoop":        (usbfs_snoop,
        "usbcore.usbfs_snoop=Y: raw USB traffic into the kernel ring buffer"),
}

def apply(cfg_protections):
    """Returns [(name, enabled, ok, detail)] for reporting."""
    results = []
    for name, (fn, desc) in REGISTRY.items():
        want = bool(cfg_protections.get(name, False))
        if not want:
            results.append((name, False, None, desc)); continue
        if not is_root():
            results.append((name, True, False, "needs root")); continue
        n, detail = fn(True)
        ok = n > 0 or "not supported" not in detail and "not available" not in detail
        results.append((name, True, ok, detail))
        if ok: _applied.append(name)
    return results

WITHHELD = set()      # sysfs device dirs that enumerated while our gate was down

def note_withheld(sysfs):
    """Record a device that arrived unauthorized because of us, so exit can revive it."""
    if sysfs: WITHHELD.add(sysfs)

def restore_all():
    """Put every touched sysfs value back. Registered with atexit and signals."""
    n = 0
    for path, val in list(_saved.items()):
        try:
            open(path, "w").write(val); n += 1
        except Exception:
            pass
    _saved.clear()
    # Restoring the gate does NOT revive anything that arrived while it was down. The
    # kernel copies authorized_default into a device's `authorized` once, at enumeration
    # time, so a device admitted under a closed gate stays at authorized=0 forever and
    # its interfaces never appear. Putting the default back changes nothing for it.
    #
    # That is the lockout this tool exists to prevent, arriving by the back door: plug a
    # keyboard in mid-session, exit cleanly, and the keyboard is dead until it is
    # physically replugged. So re-authorize exactly the devices we withheld, and no
    # others: a device someone else deauthorized on purpose is not ours to touch.
    for sysfs in sorted(WITHHELD):
        try:
            if authorize(path=sysfs): n += 1
        except Exception:
            pass
    WITHHELD.clear()
    return n

_cleanups = []

def add_cleanup(fn):
    """Run fn before we exit, including from a signal handler.

    The signal path calls os._exit, which is deliberate (it is the only reliable way
    out of a handler) but it bypasses atexit AND context managers. Anything that puts
    the terminal into a non-default state has to register here or it will leave the
    user staring at an alternate screen with no cursor.
    """
    _cleanups.append(fn)

def install_handlers(on_exit=None):
    def _bye(signum=None, frame=None):
        for fn in reversed(_cleanups):
            try:
                fn()
            except Exception as e:
                # Do NOT swallow this. A failed cleanup is how a machine gets left with
                # a dead keyboard, and a silent except is how nobody finds out.
                try: print("  cleanup failed: %s" % e, flush=True)
                except Exception: pass
        n = restore_all()
        if on_exit: on_exit(n)
        if signum: os._exit(0)
    atexit.register(_bye)
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try: signal.signal(s, _bye)
        except Exception: pass

def authorize(vid_pid=None, path=None, interfaces=True):
    """Let a specific device, and its interfaces, actually bind.

    Authorising is not enough on its own. The kernel matches drivers at authorisation
    time, so writing 1 to `authorized` after a device has already enumerated unauthorised
    leaves it admitted but UNDRIVEN. For most devices that is merely useless. For a hub it
    is actively confusing: the hub is authorised, no `hub` driver is bound, so its
    downstream ports stay dead and nothing plugged into it enumerates at all. The operator
    sees a device they just allowed, plus total silence behind it.

    So after authorising, ask the bus to re-run driver matching for each interface.
    """
    done = []
    for d in glob.glob("/sys/bus/usb/devices/*/"):
        if not os.path.exists(os.path.join(d, "idVendor")): continue
        vp = f"{_read(os.path.join(d,'idVendor'))}:{_read(os.path.join(d,'idProduct'))}"
        if vid_pid and vp != vid_pid: continue
        name = os.path.basename(d.rstrip("/"))
        if _w(os.path.join(d, "authorized"), 1): done.append(name)
        if interfaces:
            for iface in glob.glob(os.path.join(d, "*:*")):
                _w(os.path.join(iface, "authorized"), 1)
                trigger_probe(os.path.basename(iface))
    return done

def trigger_probe(iface_name):
    """Ask the USB bus to re-run driver matching for one interface.

    /sys/bus/usb/drivers_probe takes a device name and re-runs the match. Without this,
    an interface authorised after the fact never gets a driver.
    """
    try:
        with open("/sys/bus/usb/drivers_probe", "w") as f:
            f.write(iface_name)
        return True
    except Exception:
        return False
