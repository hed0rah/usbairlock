"""capture -- read what a HID device TYPES, without letting it reach the system.

The point: a BadUSB device is only interesting if you can see its payload. Blocking it
tells you it is hostile. Capturing it tells you what it was trying to do.

Two ways to do this, and this module takes the safe one.

  The tempting way is to authorize the device, let usbhid bind, then EVIOCGRAB the
  resulting /dev/input/eventN so keystrokes stop propagating. That works, but there is a
  race between bind and grab, and a payload that starts typing immediately lands in
  whatever had focus.

  This module instead claims the interface through usbfs and reads the interrupt endpoint
  directly. usbhid never binds, so the kernel never creates an input device, so the
  keystrokes have nowhere to go except this log. The leak window does not exist rather
  than being small.

Boot-protocol keyboards send 8-byte reports: byte 0 is the modifier bitmap, byte 1 is
reserved, bytes 2..7 are up to six simultaneous keycodes (HID usage IDs, not ASCII).
"""
import ctypes, fcntl, os, struct, time
from . import rules

# --- ioctl numbers, computed rather than hardcoded ---------------------------
_IOC_NRBITS, _IOC_TYPEBITS, _IOC_SIZEBITS = 8, 8, 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_NONE, _IOC_WRITE, _IOC_READ = 0, 1, 2

def _IOC(d, t, nr, size):
    return (d << _IOC_DIRSHIFT) | (ord(t) << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)

class _BulkTransfer(ctypes.Structure):
    _fields_ = [("ep", ctypes.c_uint), ("len", ctypes.c_uint),
                ("timeout", ctypes.c_uint), ("data", ctypes.c_void_p)]

USBDEVFS_BULK             = _IOC(_IOC_READ | _IOC_WRITE, 'U', 2, ctypes.sizeof(_BulkTransfer))
USBDEVFS_CLAIMINTERFACE   = _IOC(_IOC_READ, 'U', 15, 4)
USBDEVFS_RELEASEINTERFACE = _IOC(_IOC_READ, 'U', 16, 4)

# HID tables and the decoder live in rules.py, which has no imports so an
# embedded port can transliterate them directly.

def decode(report, prev_keys):
    """Delegates to the portable core."""
    return rules.decode_hid_report(report, prev_keys)


def find_node(vid, pid):
    """/dev/bus/usb/BBB/DDD for a vid:pid, read from sysfs."""
    import glob
    for d in glob.glob("/sys/bus/usb/devices/*/"):
        try:
            if open(d+"idVendor").read().strip() != vid: continue
            if open(d+"idProduct").read().strip() != pid: continue
            b = int(open(d+"busnum").read()); n = int(open(d+"devnum").read())
            return f"/dev/bus/usb/{b:03d}/{n:03d}"
        except Exception: continue
    return None

def hid_driver_present():
    return os.path.isdir("/sys/bus/usb/drivers/usbhid")

def prepare(vid_pid, interface=0):
    """Make the interface claimable WITHOUT ever letting usbhid bind to it.

    Learned the hard way, in this order:
      1. An UNAUTHORIZED device has no interfaces at all, so there is nothing to claim.
         The claim fails ENOENT. Holding the door shut also hides what is behind it.
      2. An unauthorized INTERFACE cannot be claimed either. That fails ENODEV.
      3. So the interface must be authorized, which normally invites usbhid to bind and
         turn keystrokes into input events.

    The way out is to remove usbhid FIRST. With no HID driver present, authorizing the
    interface creates nothing to bind it, so usbfs can claim it and the kernel never makes
    an input device. That is a real zero-race guarantee rather than a small window: the
    driver does not exist, so it cannot win a race.

    Returns (steps_taken, restore_fn).
    """
    import glob, subprocess
    vid, pid = vid_pid.split(":")
    steps, undo = [], []

    # NOTE: deliberately NOT `modprobe -r usbhid`. That is global, so it would kill every
    # other HID device on the machine, including the keyboard the operator is typing on if
    # this is a desktop. Unbind usbhid from THIS interface only, which leaves everything
    # else alone and reverses cleanly.

    dev = None
    for d in glob.glob("/sys/bus/usb/devices/*/"):
        try:
            if open(d+"idVendor").read().strip()==vid and open(d+"idProduct").read().strip()==pid:
                dev = d; break
        except Exception: continue
    if not dev:
        # Yanked between the arrival snapshot and this thread starting. Not a failure,
        # just a device that left. Say so with the same words as any other departure.
        raise Gone(f"{vid_pid} left before capture could start")

    def _w(path, val):
        try:
            prev = open(path).read().strip()
            open(path, "w").write(str(val))
            undo.append(lambda p=path, v=prev: open(p, "w").write(v))
            return True
        except Exception: return False

    if open(dev+"authorized").read().strip() != "1":
        if _w(dev+"authorized", 1):
            # Say this plainly. Capture cannot read an interface that does not exist, so
            # withhold_device has to be lifted FOR THIS DEVICE to read anything at all.
            # That is a real reduction in protection and the operator should see it
            # happen rather than discover it later.
            steps.append("NOTE authorized the device: withhold_device lifted for it, "
                         "since a withheld device exposes no interfaces to read")
            time.sleep(0.4)

    for i in sorted(glob.glob(dev+"*:*")):
        a = os.path.join(i, "authorized")
        if os.path.exists(a) and open(a).read().strip() != "1":
            if _w(a, 1): steps.append(f"authorized {os.path.basename(i)}")
    time.sleep(0.3)

    # authorizing may have let usbhid bind. Detach it from this interface only.
    for i in sorted(glob.glob(dev+"*:*")):
        name = os.path.basename(i)
        drv = os.path.join(i, "driver")
        if not os.path.exists(drv):
            continue
        which = os.path.basename(os.path.realpath(drv))
        try:
            open("/sys/bus/usb/drivers/%s/unbind" % which, "w").write(name)
            steps.append("detached %s from %s" % (which, name))
            def _rebind(w=which, n=name, path=i):
                for attempt in (0, 1):
                    try:
                        open("/sys/bus/usb/drivers/%s/bind" % w, "w").write(n)
                    except Exception:
                        pass
                    if os.path.exists(os.path.join(path, "driver")):
                        return
                    time.sleep(0.3)     # the device may still be settling after release
                raise RuntimeError("could not rebind %s to %s" % (w, n))
            undo.append(_rebind)
        except Exception as e:
            steps.append("WARNING could not detach %s from %s: %s" % (which, name, e))
    time.sleep(0.2)

    def restore():
        problems = []
        for fn in reversed(undo):
            try:
                fn()
            except Exception as e:
                problems.append(str(e))
        if problems:
            try: print("  capture restore failed: %s" % "; ".join(problems), flush=True)
            except Exception: pass
    return steps, restore

class Gone(Exception):
    """The device left. An ending, not a fault, and the two must not read alike."""

class _Reconnect(Exception):
    """The device re-enumerated. Not an error, just a new device number."""

def capture_forever(vid_pid, interface=0, endpoint=0x81, on_event=None,
                    on_lost=None, on_found=None, on_prepared=None, seconds=None):
    """capture(), but survives the device re-enumerating underneath us.

    Devices held by the airlock re-enumerate repeatedly, so a capture session that dies
    on the first disconnect is useless in exactly the configuration this tool creates.
    """
    started = time.time()
    # prepare() FIRST, always. The auto path used to go straight to capture(), which
    # tried to claim an interface that withhold_interface was holding unauthorized and died
    # ENODEV on every arrival. An unauthorized interface cannot be claimed; that is the
    # whole reason prepare() exists, and skipping it made --auto fail every time.
    prepared, undo = False, None
    # prepare() detaches drivers and authorizes interfaces. Those MUST be put back, and
    # the auto path previously captured the restore function and never called it, so a
    # captured keyboard stayed dead after exit. Register it with the same cleanup path
    # the signal handler uses, since os._exit skips finally blocks too.
    try:
        from . import protect as _protect
    except Exception:
        _protect = None
    while True:
        if seconds and time.time() - started > seconds: return
        try:
            if not prepared:
                steps, undo = prepare(vid_pid, interface)
                prepared = True
                if _protect: _protect.add_cleanup(undo)
                if on_prepared: on_prepared(steps)
            for ev in capture(vid_pid, interface, endpoint, on_event, on_lost, seconds):
                yield ev
            return
        except _Reconnect:
            for _ in range(60):               # up to ~6s for it to come back
                time.sleep(0.1)
                if find_node(*vid_pid.split(":")):
                    # it is back on the bus
                    try:
                        prepare(vid_pid, interface)
                    except Exception:
                        pass
                    prepared = True
                    if on_found: on_found()
                    break
            else:
                raise RuntimeError("device did not come back after re-enumerating")
        except RuntimeError:
            raise
        except GeneratorExit:
            if undo: undo()
            raise
        finally:
            pass

def capture(vid_pid, interface=0, endpoint=0x81, on_event=None, on_lost=None, seconds=None):
    """Claim the interface and read reports. Yields (timestamp, text, chords)."""
    vid, pid = vid_pid.split(":")
    node = find_node(vid, pid)
    if not node:
        raise Gone(f"{vid_pid} left before capture could start")
    fd = os.open(node, os.O_RDWR)
    # Cleanups run in REVERSE registration order, and prepare() registered the rebind
    # before we got here. So registering the release now means: release the usbfs claim
    # first, then rebind. That order is not cosmetic. usbhid cannot bind an interface
    # that usbfs still holds, so rebinding first silently fails and leaves the interface
    # driverless, which is how a captured keyboard stays dead after exit.
    released = [False]
    def _release():
        # Runs from the cleanup path AND from the finally below, so it has to be safe
        # twice. Closing an already-closed fd raises EBADF, and that exception used to
        # abort the remaining rebinds, leaving an interface driverless.
        if released[0]: return
        released[0] = True
        try: fcntl.ioctl(fd, USBDEVFS_RELEASEINTERFACE, struct.pack("I", interface))
        except Exception: pass
        try: os.close(fd)
        except Exception: pass
    try:
        from . import protect as _p
        _p.add_cleanup(_release)
    except Exception:
        pass
    try:
        try:
            fcntl.ioctl(fd, USBDEVFS_CLAIMINTERFACE, struct.pack("I", interface))
        except OSError as e:
            raise RuntimeError(
                f"cannot claim interface {interface}: {e}. "
                f"ENODEV means the interface is unauthorized, ENOENT means the device is") from e
        buf = ctypes.create_string_buffer(8)
        bt = _BulkTransfer(ep=endpoint, len=8, timeout=1000,
                           data=ctypes.cast(buf, ctypes.c_void_p))
        started, prev = time.time(), set()
        while True:
            if seconds and time.time() - started > seconds: return
            try:
                n = fcntl.ioctl(fd, USBDEVFS_BULK, bt)
            except OSError as e:
                if e.errno in (110, 4):        # ETIMEDOUT, EINTR: normal, no key pressed
                    continue
                # ESHUTDOWN/ENODEV/EPIPE: the device went away mid-read. Expected here:
                # a device held unauthorized never gets configured, so cheap HID firmware
                # assumes a bad link and resets itself, which changes devnum and leaves
                # this fd pointing at nothing. Re-resolve and reclaim rather than dying.
                if e.errno in (108, 19, 32):
                    if on_lost: on_lost()
                    raise _Reconnect()
                raise
            if n <= 0: continue
            text, chords, prev = decode(buf.raw[:n], prev)
            if text or chords:
                ev = (time.time(), text, chords)
                if on_event: on_event(*ev)
                yield ev
    finally:
        _release()
