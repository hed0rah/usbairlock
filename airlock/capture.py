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
  keystrokes have nowhere to go except this log.

  That is only true because driver auto-binding is suspended bus-wide
  (/sys/bus/usb/drivers_autoprobe) BEFORE the interface is authorized. Authorizing first
  and detaching usbhid afterwards leaves a real window, and on 2026-08-22 a key held
  across a re-enumeration came through it into the operator's terminal.

Boot-protocol keyboards send 8-byte reports: byte 0 is the modifier bitmap, byte 1 is
reserved, bytes 2..7 are up to six simultaneous keycodes (HID usage IDs, not ASCII).
"""
import ctypes, errno, fcntl, os, struct, time
from . import rules

try:
    from . import protect as _protect_mod
except Exception:                      # importable standalone for tests
    _protect_mod = None

# Bus-wide switch for automatic driver binding. Writing 0 stops the kernel binding a
# driver to any interface that becomes available while it is off, which is the only way
# to authorize an interface without racing usbhid for it.
AUTOPROBE = "/sys/bus/usb/drivers_autoprobe"

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

class _CtrlTransfer(ctypes.Structure):
    """struct usbdevfs_ctrltransfer. Naturally aligned, not packed: the u32 timeout
    lands at offset 8 and the pointer at 16 on 64-bit, which is what ctypes does by
    default. Do not add _pack_."""
    _fields_ = [("bRequestType", ctypes.c_uint8), ("bRequest", ctypes.c_uint8),
                ("wValue", ctypes.c_uint16), ("wIndex", ctypes.c_uint16),
                ("wLength", ctypes.c_uint16), ("timeout", ctypes.c_uint32),
                ("data", ctypes.c_void_p)]

USBDEVFS_BULK             = _IOC(_IOC_READ | _IOC_WRITE, 'U', 2, ctypes.sizeof(_BulkTransfer))
USBDEVFS_CONTROL          = _IOC(_IOC_READ | _IOC_WRITE, 'U', 0, ctypes.sizeof(_CtrlTransfer))
USBDEVFS_CLAIMINTERFACE   = _IOC(_IOC_READ, 'U', 15, 4)
USBDEVFS_RELEASEINTERFACE = _IOC(_IOC_READ, 'U', 16, 4)

# HID tables and the decoder live in rules.py, which has no imports so an
# embedded port can transliterate them directly.

def decode(report, prev_keys):
    """Delegates to the portable core."""
    return rules.decode_hid_report(report, prev_keys)


def dev_dir(spec):
    """The sysfs dir for a device spec, or None.

    One lookup for the whole module. This used to be three separate first-match globs
    (here, in prepare, and in capture), which meant a vid:pid shared by two devices
    could resolve to a DIFFERENT one in each, and the capture would claim one device's
    interface while unbinding another's driver.
    """
    from . import usbinfo
    hits = usbinfo.resolve(spec)
    return hits[0] if hits else None


def endpoint_packet_size(spec, interface, endpoint, default=8):
    """wMaxPacketSize for one endpoint, from sysfs. Bytes.

    This exists because the read below asked usbfs for a fixed 8 bytes, which is the
    size of a BOOT keyboard report but not of the endpoint that carries it. usbfs
    returns EOVERFLOW when the device sends a packet larger than the transfer asked
    for, so any HID interface with a bigger interrupt endpoint could not be captured
    at all -- it was detected, blocked, and then

        capture failed 146d:c529 [Errno 75] Value too large for defined data type

    Observed 2026-08-23 with a Flipper Zero running BadUSB, whose endpoint is 16 bytes.
    NKRO keyboards and anything using report IDs are the same shape. The class of device
    this program exists for was the class it could not record.
    """
    d = dev_dir(spec)
    if not d:
        return default
    import glob as _glob
    want = "ep_%02x" % (endpoint & 0xFF)
    base = os.path.basename(d.rstrip("/"))
    pats = [os.path.join(d, "%s:*.%d" % (base, interface), want, "wMaxPacketSize"),
            os.path.join(d, "*:*", want, "wMaxPacketSize")]      # fallback, any interface
    for pat in pats:
      for path in sorted(_glob.glob(pat)):
        try:
            # sysfs prints it as hex with no prefix. The low 11 bits are the size; bits
            # 11-12 are the additional-transactions field on high-speed periodic
            # endpoints and are not part of it.
            return max(default, int(open(path).read().strip(), 16) & 0x7FF)
        except Exception:
            pass
    return default


def find_node(spec):
    """/dev/bus/usb/BBB/DDD for a device spec, read from sysfs."""
    d = dev_dir(spec)
    if not d:
        return None
    try:
        b = int(open(d + "busnum").read()); n = int(open(d + "devnum").read())
        return f"/dev/bus/usb/{b:03d}/{n:03d}"
    except Exception:
        return None

def control_in(node_or_spec, bRequestType, bRequest, wValue, wIndex, length,
               timeout=1000):
    """One device-to-host control transfer on endpoint 0. Returns bytes, or None.

    Endpoint 0 belongs to the DEVICE, not to any interface, so every standard request
    here works while the interface gate is shut and no driver is bound. That is the whole
    reason --interrogate exists: a device held at the airlock can still be made to answer
    for itself, in detail, with no ability to act.

    Returns None on any refusal. A device declining a request is a FACT about the device,
    not an error here, and the caller reports it as such.
    """
    node = node_or_spec if str(node_or_spec).startswith("/dev/") else find_node(node_or_spec)
    if not node:
        return None
    length = max(0, min(int(length), 65535))
    buf = ctypes.create_string_buffer(length or 1)
    ct = _CtrlTransfer(bRequestType=bRequestType, bRequest=bRequest, wValue=wValue,
                       wIndex=wIndex, wLength=length, timeout=timeout,
                       data=ctypes.cast(buf, ctypes.c_void_p))
    try:
        fd = os.open(node, os.O_RDWR)
    except OSError:
        return None
    try:
        n = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
        return bytes(buf.raw[:n]) if n and n >= 0 else None
    except OSError:
        return None
    finally:
        try: os.close(fd)
        except Exception: pass


# GET_DESCRIPTOR types worth asking for by hand. The kernel fetches DEVICE and CONFIG
# during enumeration and caches them; the rest it never requests, so they are only
# visible if you ask.
DESC_DEVICE, DESC_CONFIG, DESC_STRING = 1, 2, 3
DESC_QUALIFIER, DESC_OTHER_SPEED, DESC_BOS = 6, 7, 15


def get_descriptor(spec, dtype, index=0, length=255, lang=0):
    return control_in(spec, 0x80, 0x06, (dtype << 8) | index, lang, length)


def get_status(spec):
    """Device status: bit 0 self-powered, bit 1 remote-wakeup ENABLED.

    Worth having because the configuration descriptor says what a device is CAPABLE of;
    this says what is currently switched on. A device with remote wakeup actually enabled
    can bring the machine out of suspend.
    """
    b = control_in(spec, 0x80, 0x00, 0, 0, 2)
    return (b[0] | (b[1] << 8)) if b and len(b) >= 2 else None


def get_configuration(spec):
    b = control_in(spec, 0x80, 0x08, 0, 0, 1)
    return b[0] if b else None


def string_descriptor(spec, index, lang=0x0409):
    """One string descriptor, decoded from UTF-16LE. None if the device refuses."""
    if not index:
        return None
    b = get_descriptor(spec, DESC_STRING, index, 255, lang)
    if not b or len(b) < 4 or b[1] != DESC_STRING:
        return None
    try:
        return b[2:b[0] if b[0] <= len(b) else len(b)].decode("utf-16-le", "replace").strip("\x00")
    except Exception:
        return None


def string_languages(spec):
    """String descriptor 0 is the list of LANGIDs the device supports."""
    b = get_descriptor(spec, DESC_STRING, 0, 255, 0)
    if not b or len(b) < 4:
        return []
    return [b[i] | (b[i + 1] << 8) for i in range(2, min(b[0], len(b)) - 1, 2)]


MS_OS_STRING_INDEX = 0xEE


def ms_os_descriptor(spec):
    """Microsoft OS descriptors: (vendor_code, compat_ids) or None.

    A two-step handshake. String index 0xEE returns a signature 'MSFT100' plus a
    vendor-specific bRequest code, which is then used for a vendor control transfer that
    returns the Extended Compat ID descriptor.

    This is a strong impersonation check and it costs one transfer. Real mass-market
    hardware overwhelmingly implements it, because Windows asks every device on first
    enumeration. A cheap board claiming to BE that hardware usually does not, because
    nothing on Linux ever asks and the author never noticed. A device answering
    146d:c529 that cannot answer what a genuine one answers has been caught by its own
    silence.
    """
    b = get_descriptor(spec, DESC_STRING, MS_OS_STRING_INDEX, 18, 0)
    if not b or len(b) < 16 or b[1] != DESC_STRING:
        return None
    try:
        sig = b[2:16].decode("utf-16-le", "replace")
    except Exception:
        return None
    if not sig.startswith("MSFT100"):
        return None
    vendor_code = b[16] if len(b) > 16 else None
    if vendor_code is None:
        return (None, [])
    # 0xC0 = device-to-host | vendor | recipient=device, wIndex 0x0004 = compat IDs
    ext = control_in(spec, 0xC0, vendor_code, 0, 0x0004, 0x28)
    compat = []
    if ext and len(ext) >= 16:
        count = ext[16] if len(ext) > 16 else 0
        for i in range(count):
            off = 16 + 8 + i * 24
            if off + 16 > len(ext):
                break
            cid = ext[off + 2:off + 10].split(b"\x00")[0].decode("ascii", "replace")
            sub = ext[off + 10:off + 18].split(b"\x00")[0].decode("ascii", "replace")
            if cid or sub:
                compat.append((cid, sub))
    return (vendor_code, compat)


def hid_driver_present():
    return os.path.isdir("/sys/bus/usb/drivers/usbhid")

def report_descriptor(vid_pid, interface=0, maxlen=4096):
    """Fetch the HID report descriptor over a control transfer. Returns bytes or None.

    This is the device's own declaration of what it can SEND, and it is the evidence the
    threat rules kept saying they lacked: "claims a raw HID interface -- no boot
    protocol, so intent is opaque without its report descriptor".

    The point is WHERE it can be read from. A standard GET_DESCRIPTOR on endpoint 0
    needs no driver and no interface claim, so this works on a device the airlock is
    holding with usbhid detached. Full declared capability, zero ability to act.

    Requesting more than the descriptor's length is fine: the device returns what it has
    and the transfer reports the real count.
    """
    node = find_node(vid_pid)
    if not node:
        return None
    buf = ctypes.create_string_buffer(maxlen)
    ct = _CtrlTransfer(
        bRequestType=0x81,       # device-to-host | standard | recipient=interface
        bRequest=0x06,           # GET_DESCRIPTOR
        wValue=(0x22 << 8),      # type 0x22 = REPORT, index 0
        wIndex=interface,
        wLength=maxlen,
        timeout=1000,
        data=ctypes.cast(buf, ctypes.c_void_p))
    try:
        fd = os.open(node, os.O_RDWR)
    except OSError:
        return None
    try:
        n = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
        return bytes(buf.raw[:n]) if n and n > 0 else None
    except OSError:
        # A device with no report descriptor, or one refusing the request, is a fact
        # about the device rather than a failure here. Say nothing and let the caller
        # report what it does know.
        return None
    finally:
        try: os.close(fd)
        except OSError: pass


def prepare(vid_pid, interface=0):
    """Make the interface claimable WITHOUT ever letting usbhid bind to it.

    Learned the hard way, in this order:
      1. An UNAUTHORIZED device has no interfaces at all, so there is nothing to claim.
         The claim fails ENOENT. Holding the door shut also hides what is behind it.
      2. An unauthorized INTERFACE cannot be claimed either. That fails ENODEV.
      3. So the interface must be authorized, which normally invites usbhid to bind and
         turn keystrokes into input events.

    The way out is to stop the bus auto-binding ANYTHING before authorizing, using
    /sys/bus/usb/drivers_autoprobe. With autoprobe off, authorizing an interface creates
    something usbfs can claim and nothing the kernel will bind a driver to, so no input
    device is ever made. Autoprobe goes back on as soon as the claim is safe.

    This used to authorize first and detach usbhid afterwards, with a 0.3s sleep in
    between and a comment admitting "authorizing may have let usbhid bind". It had.
    Observed 2026-08-22: a key held down across a re-enumeration produced a character in
    the operator's terminal, from a keyboard this tool was holding. That is precisely
    what the tool warns HIGH about -- "on bind it can inject keystrokes into your session
    immediately" -- happening inside the capture path meant to prevent it.

    Returns (steps_taken, restore_fn).
    """
    import glob, subprocess
    steps, undo = [], []

    # NOTE: deliberately NOT `modprobe -r usbhid`. That is global, so it would kill every
    # other HID device on the machine, including the keyboard the operator is typing on if
    # this is a desktop. Unbind usbhid from THIS interface only, which leaves everything
    # else alone and reverses cleanly.

    dev = dev_dir(vid_pid)
    if not dev:
        # Yanked between the arrival snapshot and this thread starting. Not a failure,
        # just a device that left. Say so with the same words as any other departure.
        raise Gone(f"{vid_pid} left before capture could start")

    def _restore_one(p, v):
        # A path that no longer exists is a device that left, not a failed restore.
        # This matters now that every re-enumeration registers its own undo: the old
        # device's sysfs paths are gone by definition once devnum changes, and reporting
        # each of them as "capture restore failed" at exit would bury a real failure in
        # noise that is guaranteed to occur.
        if not os.path.exists(p):
            return
        open(p, "w").write(v)

    def _w(path, val):
        try:
            prev = open(path).read().strip()
            open(path, "w").write(str(val))
            undo.append(lambda p=path, v=prev: _restore_one(p, v))
            return True
        except Exception: return False

    # ---- close the bind race BEFORE authorizing anything --------------------------
    # Bus-wide and brief. It only suppresses AUTOMATIC binding to interfaces that become
    # available while it is off, which is exactly the window being closed; nothing
    # already bound is disturbed. Registered with protect immediately so a crash between
    # here and the restore below cannot leave the machine unable to bind USB drivers.
    _autoprobe_prev = None
    try:
        _autoprobe_prev = open(AUTOPROBE).read().strip()
    except Exception:
        pass

    def _autoprobe_restore(v=_autoprobe_prev):
        if v is None:
            return
        try: open(AUTOPROBE, "w").write(v)
        except Exception: pass

    if _autoprobe_prev is not None:
        try:
            open(AUTOPROBE, "w").write("0")
            if _protect_mod: _protect_mod.add_cleanup(_autoprobe_restore)
            undo.append(_autoprobe_restore)
            steps.append("driver auto-binding suspended while this interface is opened")
        except Exception:
            _autoprobe_prev = None

    if open(dev+"authorized").read().strip() != "1":
        if _w(dev+"authorized", 1):
            # Say this plainly. Capture cannot read an interface that does not exist, so
            # withhold_device has to be lifted FOR THIS DEVICE to read anything at all.
            # That is a real reduction in protection and the operator should see it
            # happen rather than discover it later.
            steps.append("NOTE device gate lifted for this device only: a withheld "
                         "device exposes no interfaces at all, so there is nothing to "
                         "read. NO driver is bound; the driver gate stays shut")
            time.sleep(0.4)

    for i in sorted(glob.glob(dev+"*:*")):
        a = os.path.join(i, "authorized")
        if os.path.exists(a) and open(a).read().strip() != "1":
            # Deliberately not the word "authorized". The kernel spells device-scope
            # and interface-scope authorization the same way, and this tool spells its
            # own allow list that way too, so one log line ended up carrying three
            # meanings. Reading "authorized 1-1:1.0" while a keyboard was being held
            # looked exactly like the gate had failed. It had not: usbhid was already
            # detached, so nothing could bind, and usbfs claims it a moment later.
            if _w(a, 1):
                steps.append(f"{os.path.basename(i)} made claimable (no driver can bind, "
                             f"usbhid is detached)")
    # With autoprobe off nothing can have bound in the step above. This loop is for a
    # device that was ALREADY bound when we got here -- the common case for something
    # plugged in before the monitor started.
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
    # Auto-binding back on NOW, not at capture end. Leaving it off for the length of a
    # session would be bus-wide: plug in a mouse mid-capture and it would never get a
    # driver. Safe to restore here because the switch only affects the probe that runs
    # when an interface is REGISTERED. This interface is already registered, authorized
    # and unbound, so turning the switch back on does not retroactively bind it -- only
    # a new device event or an explicit drivers_probe would.
    _autoprobe_restore()
    time.sleep(0.2)

    done = [False]
    def restore():
        # Registered with protect.add_cleanup AND callable directly when a device is
        # allowed mid-session, so it must be safe twice. Rebinding an already-bound
        # interface raises, and that used to print "capture restore failed" at exit
        # for a device that had in fact been restored perfectly.
        if done[0]: return
        done[0] = True
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
                    on_lost=None, on_found=None, on_prepared=None, seconds=None,
                    should_stop=None):
    """capture(), but survives the device re-enumerating underneath us.

    Devices held by the airlock re-enumerate repeatedly, so a capture session that dies
    on the first disconnect is useless in exactly the configuration this tool creates.
    """
    started = time.time()
    # prepare() FIRST, always. The auto path used to go straight to capture(), which
    # tried to claim an interface that withhold_interface was holding unauthorized and died
    # ENODEV on every arrival. An unauthorized interface cannot be claimed; that is the
    # whole reason prepare() exists, and skipping it made --auto fail every time.
    # A LIST, not a single undo. prepare() runs again on every re-enumeration, and this
    # kept only the first one: the reconnect discarded prepare()'s return value entirely,
    # so its changes were never registered for cleanup and `undo` still pointed at the
    # previous device's sysfs paths. Devices held by this tool re-enumerate repeatedly --
    # that is why capture_forever exists -- so the common path was leaking authorization
    # changes past exit and "restored N kernel setting(s)" was under-reporting.
    # Each restore() is idempotent, so running them all is safe.
    prepared, undos = False, []

    def undo_all():
        for fn in reversed(undos):
            try: fn()
            except Exception: pass
    # prepare() detaches drivers and authorizes interfaces. Those MUST be put back, and
    # the auto path previously captured the restore function and never called it, so a
    # captured keyboard stayed dead after exit. Register it with the same cleanup path
    # the signal handler uses, since os._exit skips finally blocks too.
    try:
        from . import protect as _protect
    except Exception:
        _protect = None
    while True:
        # Stopping has to put the device back NOW, not at process exit. prepare()
        # detached usbhid and claimed the interface; until both are undone the device
        # is admitted on paper and still dead in practice, which is exactly what
        # --authorize looked like before this existed.
        if should_stop and should_stop():
            undo_all()
            return
        if seconds and time.time() - started > seconds: return
        try:
            if not prepared:
                steps, undo = prepare(vid_pid, interface)
                prepared = True
                undos.append(undo)
                if _protect: _protect.add_cleanup(undo)
                if on_prepared: on_prepared(steps)
            for ev in capture(vid_pid, interface, endpoint, on_event, on_lost, seconds,
                              should_stop=should_stop):
                yield ev
            return
        except _Reconnect:
            for _ in range(60):               # up to ~6s for it to come back
                if should_stop and should_stop():
                    undo_all()
                    return
                time.sleep(0.1)
                if find_node(vid_pid):
                    # it is back on the bus, with a new devnum and new interface names.
                    # Register THIS prepare's undo too, or its changes never get put
                    # back and the only registered undo points at the old paths.
                    try:
                        steps2, undo2 = prepare(vid_pid, interface)
                        undos.append(undo2)
                        if _protect: _protect.add_cleanup(undo2)
                        if on_prepared: on_prepared(steps2)
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
            undo_all()
            raise
        finally:
            pass

def capture(vid_pid, interface=0, endpoint=0x81, on_event=None, on_lost=None, seconds=None,
            should_stop=None):
    """Claim the interface and read reports. Yields (timestamp, text, chords)."""
    node = find_node(vid_pid)
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
            # Every code claimintf() in devio.c can return, in the order it checks them.
            # From usb_driver_claim_interface() in drivers/usb/core/driver.c and
            # claimintf() in devio.c: the driver check comes BEFORE the authorization
            # check, so a bound interface reports EBUSY even when it is also
            # unauthorized. EBUSY is the one a person hits most, and saying only the
            # other two sent them looking at the gate when a driver had simply got
            # there first.
            why = {
                errno.EBUSY:  "EBUSY: a driver already holds this interface. Detach it, "
                              "or run the monitor so the gate keeps drivers off",
                errno.ENODEV: "ENODEV: the interface exists but is not authorized",
                errno.ENOENT: "ENOENT: no such interface. An unauthorized DEVICE has "
                              "none at all",
                errno.EACCES: "EACCES: this usbfs handle has dropped privileges for "
                              "that interface",
                # claimintf() rejects ifnum >= 8*sizeof(ps->ifclaimed) before it looks
                # anything up, because the claim set is a bitmask one unsigned long
                # wide, so the ceiling is platform-dependent. Unreachable for a normal
                # device and entirely reachable for a hostile descriptor, which is
                # exactly the case this tool exists for.
                errno.EINVAL: "EINVAL: interface number above the usbfs ceiling "
                              "(8*sizeof(long) interfaces). Not claimable",
            }.get(e.errno, str(e))
            raise RuntimeError(f"cannot claim interface {interface}: {why}") from e
        # Ask for what the endpoint can actually send, not what a boot report weighs.
        size = endpoint_packet_size(vid_pid, interface, endpoint)
        buf = ctypes.create_string_buffer(size)
        bt = _BulkTransfer(ep=endpoint, len=size, timeout=1000,
                           data=ctypes.cast(buf, ctypes.c_void_p))
        started, prev = time.time(), set()
        while True:
            # The bulk read below has a 1000ms timeout and treats ETIMEDOUT as continue,
            # so this is reached about once a second even on a silent device. That is why
            # releasing a device does not have to wait for the next keypress.
            if should_stop and should_stop(): return
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
                # 108 ESHUTDOWN, 19 ENODEV, 32 EPIPE, 71 EPROTO. EPROTO was fatal
                # until a YubiKey threw one during a replug and took the capture down
                # with it, while the device sat there perfectly healthy.
                if e.errno in (108, 19, 32, 71):
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
