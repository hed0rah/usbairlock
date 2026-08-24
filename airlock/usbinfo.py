"""Read what a USB device says about itself, and judge the claims.

Everything a USB device reports is self-asserted. There is no authentication anywhere
in the protocol. Treat every field as a claim.
"""
import glob, os, re, shutil, subprocess
from . import rules

CLASSES = rules.CLASSES
KNOWN = rules.KNOWN

def sh(c, t=20):
    """Run a FIXED command string through a shell. Never interpolate into this.

    Kept for the couple of constant commands that want shell syntax. Anything carrying
    a value from the command line, a device, or a descriptor string must use run()
    instead -- see the note there for why that is not a style preference.
    """
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t).stdout
    except Exception: return ""

def run(argv, t=20):
    """Run an argv list with NO shell. The only safe way to pass a value to a command.

    This exists because descriptors() built `lsusb -v -d %s` with shell=True from a
    spec that comes straight off the command line, and this tool normally runs as root:

        ./usbairlock --inspect 'zz:zz; any command here; #'

    ran that command as root. A tool whose entire job is deciding what to trust cannot
    have a shell metacharacter path from argv to a privileged subprocess.
    """
    try:
        return subprocess.run(argv, shell=False, capture_output=True, text=True,
                              timeout=t).stdout
    except Exception:
        return ""

def have_lsusb():
    return bool(shutil.which("lsusb"))

def snapshot():
    """{bus/dev: {...}} for everything attached that is not a root hub.

    Reads sysfs directly rather than parsing lsusb. A triage box is often a minimal
    image with no usbutils installed, and shelling out to a missing binary returns an
    empty result that is indistinguishable from "nothing is plugged in". Reporting a
    blind tool as a clean bill of health is the worst failure this program could have.
    lsusb is still used for verbose interface descriptors, where it adds real detail.
    """
    out = {}
    for d in sorted(glob.glob("/sys/bus/usb/devices/*/")):
        base = os.path.basename(d.rstrip("/"))
        if base.startswith("usb"):            # root hub
            continue
        vid, pid = _attr(d, "idVendor"), _attr(d, "idProduct")
        if not vid or not pid:                # an interface dir, not a device
            continue
        # Hubs are NOT hidden. An earlier version skipped them as infrastructure, and
        # the result was plugging a hub in and seeing nothing at all, which reads as a
        # broken tool. A hub is also a real surface: a hostile device can present as a
        # hub with a keyboard behind it, and an unauthorized hub silently kills every
        # port downstream of it. Mark it, do not drop it.
        is_hub = _attr(d, "bDeviceClass") == "09"
        busnum, devnum = _attr(d, "busnum") or "?", _attr(d, "devnum") or "?"
        product = safe_text(_attr(d, "product"))
        vendor  = safe_text(_attr(d, "manufacturer"))
        name = (f"{vendor} {product}".strip()) or ""
        out[f"{int(busnum):03d}/{int(devnum):03d}" if busnum.isdigit() and devnum.isdigit()
            else base] = {
            "bus": busnum, "dev": devnum, "id": f"{vid}:{pid}",
            "name": name, "sysfs": d, "is_hub": is_hub,
                "authorized": _attr(d, "authorized"),
        }
    return out

def resolve(spec):
    """Every sysfs device dir matching a spec, most specific form first.

        1-2                    sysfs name, the bus-port chain. UNIQUE.
        001/089  1:89          bus and device number. UNIQUE until replug.
        /dev/bus/usb/001/089   the usbfs node. UNIQUE until replug.
        1a2c:2d23              vid:pid. MAY MATCH SEVERAL DEVICES.

    Returns a list, deliberately. vid:pid is a MODEL identifier, not a device
    identifier: plug in two of the same keyboard and it names both. Every caller
    that wants one device has to decide what to do about the second, rather than
    silently taking whichever the filesystem listed first, which is what this
    used to do.
    """
    spec = (spec or "").strip()
    if not spec:
        return []
    devs = [d for d in sorted(glob.glob("/sys/bus/usb/devices/*/"))
            if _attr(d, "idVendor") and _attr(d, "idProduct")]

    if spec.startswith("/dev/bus/usb/"):
        parts = spec.rstrip("/").split("/")
        spec = "%s/%s" % (parts[-2], parts[-1])

    if ":" in spec and "-" not in spec:
        left, right = spec.split(":", 1)
        if len(left) == 4 and len(right) == 4:          # vid:pid
            v, pid = left.lower(), right.lower()
            return [d for d in devs
                    if (_attr(d, "idVendor") or "").lower() == v
                    and (_attr(d, "idProduct") or "").lower() == pid]
        spec = "%s/%s" % (left, right)                   # bus:devnum

    if "/" in spec:                                      # bus/devnum
        b, n = spec.split("/", 1)
        try: b, n = int(b), int(n)
        except ValueError: return []
        return [d for d in devs
                if _int(_attr(d, "busnum")) == b and _int(_attr(d, "devnum")) == n]

    return [d for d in devs if os.path.basename(d.rstrip("/")) == spec]


# Anything the DEVICE supplies -- iProduct, iManufacturer, iSerial -- is attacker
# controlled text that this tool prints to a terminal, writes to a log and emits as
# tab-separated porcelain. Left raw it can do all three of:
#
#   \x1b[2A\x1b[2K   move up two lines and erase them, over the [HIGH] verdict that
#                     was just printed about this very device
#   \n               forge an extra record in line-oriented output
#   \t               break a porcelain field boundary
#
# A device rewriting the tool's conclusion about itself is the one output bug this
# program cannot have, so device text is sanitized where it is READ, not where it is
# printed. There is no second place to forget.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

def power_claim(cfg_attrs):
    """Decode bmAttributes into what the device CLAIMS about its own power.

    bit 6 self-powered, bit 5 remote wakeup, bit 7 reserved and always set.

    Worth surfacing rather than leaving in the raw byte, because it is a claim and
    devices lie about it. A bus-powered hub reporting self-powered tells the kernel each
    downstream port may draw a full load; the kernel believes it, allows it, and the
    devices behind it brown out with no power rejection logged anywhere, because nothing
    was ever rejected. Two such hubs were measured here reporting exactly that.
    """
    # ALWAYS base 16. The regex that captures this strips the "0x", so the value arrives
    # as bare hex digits -- and "80" is all-decimal-digits while meaning 0x80. Trying
    # decimal first turned a bus-powered device into a self-powered one, which is the
    # tool lying about hardware rather than merely being unhelpful.
    try:
        v = int(str(cfg_attrs), 16)
    except (TypeError, ValueError):
        return None
    return {"self_powered": bool(v & 0x40), "remote_wakeup": bool(v & 0x20), "raw": v}


# Negotiated speed, by the USB generation that can reach it.
_SPEED_TIER = ((10000, "SuperSpeed+ (10 Gb/s)"), (5000, "SuperSpeed (5 Gb/s)"),
               (480, "High Speed (480 Mb/s)"), (12, "Full Speed (12 Mb/s)"),
               (1.5, "Low Speed (1.5 Mb/s)"))


# Kernel workarounds registered against specific hardware. Names taken verbatim from
# include/linux/usb/quirks.h. A non-zero value means the kernel already knows this exact
# device misbehaves in a named way -- which is a fact about the hardware you are holding,
# from a source with no opinion about this tool.
USB_QUIRKS = {
    1 << 0: "string-fetch-255",   1 << 1: "reset-resume",
    1 << 2: "no-set-intf",        1 << 3: "config-intf-strings",
    1 << 4: "needs-reset",        1 << 5: "honor-bnuminterfaces",
    1 << 6: "delay-init",         1 << 7: "linear-uframe-intr-binterval",
    1 << 8: "device-qualifier",   1 << 9: "ignore-remote-wakeup",
    1 << 10: "no-lpm",            1 << 11: "linear-frame-intr-binterval",
    1 << 12: "disconnect-suspend", 1 << 13: "delay-ctrl-msg",
    1 << 14: "hub-slow-reset",    1 << 15: "endpoint-ignore",
    1 << 16: "short-set-address-req-timeout",
}


def quirk_names(raw):
    """Decode /sys/.../quirks into the kernel's own names for each workaround."""
    try:
        v = int(str(raw), 16) if str(raw).lower().startswith("0x") else int(str(raw))
    except (TypeError, ValueError):
        return []
    if not v:
        return []
    out = [n for bit, n in sorted(USB_QUIRKS.items()) if v & bit]
    left = v & ~sum(b for b in USB_QUIRKS if v & b)
    if left:
        out.append("0x%x" % left)          # a newer kernel than this table knows about
    return out


def port_location(devdir):
    """Where the connector physically is, from ACPI, or None.

    Every device has a `port` symlink. Ports on the machine itself carry a
    physical_location the firmware filled in; ports on a downstream hub do not, because
    firmware only describes its own chassis. So this answers "which socket" for something
    plugged into the computer, and says nothing for something behind a hub -- which is
    honest, since nothing knows.
    """
    port = os.path.join(devdir or "", "port")
    loc = os.path.join(port, "physical_location")
    if not os.path.isdir(loc):
        return None
    panel = _attr(loc, "panel")
    horiz = _attr(loc, "horizontal_position")
    vert = _attr(loc, "vertical_position")
    if not panel or panel == "unknown":
        return None
    where = " ".join(x for x in (vert, horiz) if x and x != "unknown")
    out = f"{where} {panel} panel".strip() if where else f"{panel} panel"
    if _attr(loc, "dock") == "yes":
        out += ", on a dock"
    if _attr(loc, "lid") == "yes":
        out += ", on the lid"
    ct = _attr(port, "connect_type")
    if ct and ct != "unknown":
        out += f" ({ct})"
    return out


def attachment(removable, addr=None):
    """Whether the port this sits on is user-accessible, and WHO says so.

    `fixed` means not user-accessible -- a soldered webcam or bluetooth module.
    `removable` means it is. Useful for triage in the plainest way: it separates what
    was already inside the machine from what somebody attached to it.

    But only when the parent is a ROOT hub. This function used to assume anything
    behind a hub reported `unknown`, "because firmware only describes the ports on the
    machine itself". That is false, and a keyboard on a GenesysLogic hub disproved it on
    2026-08-23:

        1-4.4  removable=fixed   parent=1-4      -> "internal, soldered to this machine"

    A hub supplies this for its own ports, from the DeviceRemovable bitmap in its hub
    descriptor. So the tool was taking a HUB's self-assertion and rendering it as a
    statement about the machine's construction, which is a trust signal. A hostile hub
    sets that bit and everything plugged into it reads as built-in hardware.

    Everything a USB device reports is self-asserted, including this. Say whose claim it
    is. `addr` is the DEVICE's own address; the parent is derived from it here so no
    caller can get the relationship the wrong way round. Pass none to get the old
    unqualified wording.
    """
    v = (removable or "").strip().lower()
    if v not in ("fixed", "removable"):
        return None
    parent = parent_of(addr) if addr else None
    if parent is None or str(parent).startswith("usb"):     # root hub: ACPI describes it
        return {"fixed": "internal, soldered to this machine",
                "removable": "user-accessible port"}[v]
    return {"fixed": "the parent hub calls this port non-removable -- that hub's claim, "
                     "not the machine's",
            "removable": "user-accessible port on an external hub"}[v]


def link_note(usb_version, speed):
    """A note when a link negotiated well below what the device declares, or None.

    Deliberately narrow. Almost every device that runs slower than its declared version
    is doing so on purpose: a Bluetooth adapter declaring USB 2.01 and running at 12
    Mb/s has no use for High Speed, and flagging that would bury the one case that
    actually means something.

    That case is a USB 3 device on a link below SuperSpeed. There is no design reason
    for it, so it is one of: a USB 2 cable, a USB 2 port, or a USB 2 hub somewhere in
    the chain. All three are things the operator can fix and would want to know about.
    """
    try:
        ver = float(str(usb_version))
        spd = float(str(speed))
    except (TypeError, ValueError):
        return None
    if ver >= 3.0 and spd < 5000:
        return ("declares USB %.2f but negotiated %s -- a USB 2 path. "
                "Check the cable, the port, and for a 2.0 hub in the chain"
                % (ver, speed_name(spd)))
    return None


def speed_name(speed):
    try: spd = float(str(speed))
    except (TypeError, ValueError): return str(speed)
    for floor, name in _SPEED_TIER:
        if spd >= floor:
            return name
    return "%s Mb/s" % speed


_EP_SHORT = {"isochronous": "iso", "interrupt": "int", "bulk": "bulk", "control": "ctrl"}


def endpoint_label(ep, verbose=False):
    """A readable endpoint.

    Accepts the structured form the descriptor parser produces, and a bare address
    string for anything still holding one.
    """
    if isinstance(ep, dict):
        base = "ep%s %s %s" % (ep.get("num"), ep.get("dir"),
                               _EP_SHORT.get(ep.get("type"), ep.get("type")))
        if not verbose:
            return base
        return "%s  %sB  every %s" % (base, ep.get("max_packet"), _interval(ep))
    try:
        v = int(str(ep), 16)
    except (TypeError, ValueError):
        return str(ep)
    return "ep%d %s" % (v & 0x0F, "IN" if v & 0x80 else "OUT")


def _interval(ep):
    """bInterval in something a person can read.

    Its meaning depends on speed and transfer type, which is why it is so often
    misreported. For interrupt and isochronous at high speed it is 2^(n-1) microframes
    of 125us; at full and low speed it is n milliseconds. Bulk and control ignore it.
    """
    n = _int(ep.get("interval"))
    if n is None:
        return "?"
    if ep.get("type") in ("bulk", "control"):
        return "n/a"
    return "%s frame%s" % (n, "" if n == 1 else "s")


def safe_text(v, limit=200):
    """Device-supplied text, made safe to print, log and parse. Never bypass this."""
    t = str(v or "").replace("\t", " ")
    t = _UNSAFE.sub("?", t)
    return t[:limit] + "..." if len(t) > limit else t


def _int(v):
    try: return int(v)
    except (TypeError, ValueError): return None


def addr_of(d):
    """The stable address of a sysfs device dir: its bus-port chain, eg 1-2."""
    return os.path.basename((d or "").rstrip("/")) or None


def id_of(d):
    """vid:pid for a sysfs device dir, or None.

    The allow list is matched on this, so anything WRITING to that list has to speak the
    same language. --authorize used to store the operator's raw argument, which meant an
    address went in whenever one was typed and matched nothing forever after.
    """
    d = (d or "")
    if d and not d.endswith(os.sep):
        d += os.sep
    v, pr = _attr(d, "idVendor"), _attr(d, "idProduct")
    return "%s:%s" % (v, pr) if v and pr else None


def parent_of(addr):
    """The address of the hub a device hangs off, or None for a root hub.

    sysfs already encodes the whole tree in the name, so this needs no lookups:

        usb1        a root hub, the top of a bus
        1-2         port 2 of root hub usb1
        1-2.3       port 3 of the hub that is itself on 1-2
        1-2.3.4     and so on, one dot per hub you pass through

    That is why topology is worth showing. An unauthorized hub silently kills every
    port beneath it, so the operator sees a device they allowed and total silence
    behind it, with nothing in any log to explain why.
    """
    if not addr or addr.startswith("usb"):
        return None
    if "." in addr:
        return addr.rsplit(".", 1)[0]
    bus = addr.split("-", 1)[0]
    return "usb" + bus if bus.isdigit() else None


def depth_of(addr):
    """How many hubs deep a device sits. 0 for a root hub, 1 for directly attached."""
    if not addr or addr.startswith("usb"):
        return 0
    return addr.count(".") + 1


def sort_key(addr):
    """Port order, not string order. `1-5` sorts before `1-14`.

    The obvious sort is on the sysfs name, which puts port 14 ahead of port 5 because
    it compares "1" against "5" one character at a time. A ten-port hub then lists in
    an order that matches nothing printed on the plastic. Splitting on the separators
    and comparing the port numbers as numbers is the whole fix.

    Root hubs sort first within their bus, so `usb1` heads the `1-*` devices.
    """
    if not addr:
        return ()
    if addr.startswith("usb"):
        return (_int(addr[3:]) or 0,)
    bus, _, ports = addr.partition("-")
    return (_int(bus) or 0, 1) + tuple(_int(x) or 0 for x in ports.split("."))


def blinds_downstream(addr, authorized, is_hub, driver=None):
    """Is this a HUB with no driver, i.e. one that is hiding whatever is behind it.

    This replaces a stranded_by() that walked UP from a device to find a shut hub
    above it. Proven unreachable on real hardware 2026-08-22: a withheld hub binds no
    driver, so nothing behind it ever enumerates, so the children do not exist in
    sysfs to be marked. Plugging a dock holding two devices into a closed gate listed
    the hub alone and the two devices simply vanished from the tree.

    So the warning belongs on the hub, which does exist, and it has to be phrased as
    "you cannot see what is behind this" rather than "these are unreachable" -- the
    tool genuinely does not know what is back there. That is the whole point: an
    unauthorized hub is an opaque surface, and a hostile device can present as one.

    The test is the DRIVER, not the device gate, and that distinction is the whole
    correctness of this function. It first checked `authorized == "0"`, which only ever
    fires under withhold_device. The default protection is withhold_interface, which
    leaves the device authorized and shuts the interface instead -- so a hub held by the
    DEFAULT configuration was exactly as opaque and said nothing at all.

    Proven on hardware 2026-08-23 with a VIA Labs dual-personality hub:

        1-4  device authorized=1   iface 1-4:1.0 authorized=0   driver: none
        kernel: hub 1-4:1.0: Interface 0 is not authorized for usage

    Nothing behind it can enumerate, because no hub driver is bound. Whether the gate
    that stopped the bind was the device one or the interface one does not matter to
    anything downstream, so it must not matter here either.

    Passing driver=None keeps the old device-gate-only behaviour, for callers that have
    no driver information to give.
    """
    if not is_hub or str(addr).startswith("usb"):
        return False
    if authorized.get(addr) == "0":
        return True
    if driver is None:                      # caller cannot tell us; do not guess
        return False
    return str(driver).strip().lower() in ("", "-", "none")


def stranded_by(addr, authorized):
    """The nearest ancestor hub that is unauthorized, or None.

    Retained because it is correct for a tree someone ELSE deauthorized -- a hub shut
    by udev, another tool, or by hand after its children had already enumerated. It is
    just not reachable through this tool's own gate. See blinds_downstream().
    """
    seen, up = set(), parent_of(addr)
    while up and up not in seen:
        seen.add(up)
        if authorized.get(up) == "0":
            return up
        up = parent_of(up)
    return None


def sysfs_for(spec):
    """One device dir for a spec, or None. Ambiguity resolves to the first match."""
    hits = resolve(spec)
    return hits[0] if hits else None

def _attr(d, name):
    try: return open(os.path.join(d, name)).read().strip()
    except Exception: return None

def descriptors(spec):
    """Everything structural about a device, from its own descriptor bytes.

    The kernel exposes the raw device and configuration descriptors at
    /sys/bus/usb/devices/*/descriptors, exactly as the device sent them. Parsing those
    directly is the primary path, and it is better than the alternative in three ways:

      - no external dependency. lsusb is a text scrape of these same bytes, and a triage
        box is precisely the machine that will not have usbutils installed.
      - no subprocess, so no shell, no argument handling, and it is faster.
      - more accurate. The text scrape collapsed alternate settings, so an audio
        interface with its endpoints on alt 1 appeared to have none at all. Endpoint
        transfer type, max packet size and interval were not available either.

    lsusb is still consulted for one thing when it exists: the iInterface strings, which
    are string-descriptor INDICES in the blob rather than text. Nothing depends on it.
    """
    d = sysfs_for(spec)
    if d:
        try:
            with open(os.path.join(d, "descriptors"), "rb") as fh:
                blob = fh.read()
            parsed = rules.parse_descriptors(blob)
            if parsed.get("id"):
                return _enrich(parsed, d, spec)
        except OSError:
            pass          # unreadable without root; fall through to lsusb
    return _descriptors_lsusb(spec, d)


def _hid_reports(dev, d, spec):
    """Fetch the report descriptor for any HID interface no driver is holding.

    Deliberately narrow. It is a real control transfer to the device, so it runs only
    when it can succeed and only when it says something not already known:
      - HID class, and NOT boot protocol. A boot keyboard has already declared itself.
      - no driver bound: the kernel returns EBUSY for a control transfer aimed at an
        interface a driver owns. That is exactly the state the airlock creates, so this
        reads a held device and does not bother a working one.
      - root, since it needs the usbfs node.
    """
    rds = {}
    for i in sorted(glob.glob(os.path.join(d, "*:*"))):
        try:
            if _attr(i, "bInterfaceClass") != "03":            continue
            if _attr(i, "bInterfaceProtocol") in ("01", "02"): continue
            if os.path.exists(os.path.join(i, "driver")):      continue
            num = _attr(i, "bInterfaceNumber")
            if num is None:                                    continue
            n = int(num, 16) if not str(num).isdigit() else int(num)
            from . import capture as _cap
            raw = _cap.report_descriptor(spec, n)
            if raw:
                rds[str(n)] = raw
        except Exception:
            continue        # a device that will not answer is a fact, not a fault
    if rds:
        dev["report_descriptors"] = rds
    return dev


def _enrich(dev, d, spec):
    """Add what sysfs knows and the blob does not: resolved strings, live driver state."""
    dev["addr"] = addr_of(d)
    dev["bus"], dev["devnum"] = _attr(d, "busnum"), _attr(d, "devnum")
    dev["speed"] = _attr(d, "speed")
    dev["authorized"] = _attr(d, "authorized")
    dev["maxchild"] = _attr(d, "maxchild")
    dev["removable"] = _attr(d, "removable")
    dev["quirks"] = _attr(d, "quirks")
    # The live configuration. 0 means UNCONFIGURED, which is the precise state a
    # withheld device is in: usb_set_configuration() forces configuration 0 when
    # dev->authorized is 0, and an unconfigured device has no interfaces by the USB
    # spec's own rules. "no interface objects" is the consequence; this is the cause.
    dev["config_value"] = _attr(d, "bConfigurationValue")
    # Strings are indices in the descriptor blob; the kernel has already resolved them.
    for k, a in (("manufacturer", "manufacturer"), ("product", "product"),
                 ("serial", "serial")):
        v = _attr(d, a)
        if v: dev[k] = safe_text(v)
    drivers = []
    for i in glob.glob(os.path.join(d, "*:*")):
        drv = os.path.join(i, "driver")
        if os.path.exists(drv):
            drivers.append(os.path.basename(os.path.realpath(drv)))
    dev["drivers"] = sorted(set(drivers))
    _hid_reports(dev, d, spec)
    return dev


def _descriptors_lsusb(spec, d):
    """Fallback: parse lsusb -v. Only reached when the raw blob cannot be read."""
    # argv, never a shell string. `spec` reaches here straight from --inspect/--capture,
    # and this runs as root. A vid:pid is also validated rather than trusted: if it does
    # not look like one, do not hand it to lsusb at all.
    sel = None
    if d:
        b, n = _int(_attr(d, "busnum")), _int(_attr(d, "devnum"))
        if b is not None and n is not None:
            sel = ["-s", "%03d:%03d" % (b, n)]
    if sel is None:
        if not re.fullmatch(r"[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}", str(spec or "")):
            return {}
        sel = ["-d", str(spec)]
    txt = run(["lsusb", "-v"] + sel, 25)
    dev = {}
    for pat, key in [(r'bcdUSB\s+([\d.]+)','usb_version'), (r'bDeviceClass\s+(\d+)','dev_class'),
                     (r'bMaxPacketSize0\s+(\d+)','ep0_size'), (r'bNumConfigurations\s+(\d+)','n_configs'),
                     (r'MaxPower\s+(\S+)','max_power'), (r'bmAttributes\s+0x([0-9a-f]+)','cfg_attrs'),
                     # [ \t]* not \s*: \s matches newlines, so an EMPTY string descriptor let the
                     # capture run onto the next line and report iProduct as the manufacturer.
                     (r'iManufacturer\s+\d+[ \t]*(.*)','manufacturer'),
                     (r'iProduct\s+\d+[ \t]*(.*)','product'),
                     (r'iSerial\s+\d+[ \t]*(.*)','serial')]:
        m = re.search(pat, txt)
        # These three come from the device's own string descriptors, via lsusb. Same
        # rule as snapshot(): sanitize at the boundary, so nothing downstream has to
        # remember to.
        if m: dev[key] = safe_text(m.group(1).strip())
    ifs, cur = [], None
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("bInterfaceNumber"):
            if cur: ifs.append(cur)
            cur = {"num": s.split()[-1], "eps": []}
        elif cur is not None:
            for pat, key in [("bInterfaceClass","cls"), ("bInterfaceSubClass","sub"),
                             ("bInterfaceProtocol","proto"), ("bNumEndpoints","n_eps")]:
                if s.startswith(pat):
                    cur[key] = s.split()[1]
            if s.startswith("bEndpointAddress"):
                cur["eps"].append(s.split()[1])
            if s.startswith("iInterface"):
                parts = s.split(None, 2)
                # iInterface is a device string too
                if len(parts) > 2: cur["name"] = safe_text(parts[2])
    if cur: ifs.append(cur)
    # collapse alternate settings: same interface number repeats per bandwidth variant
    uniq = {}
    for i in ifs:
        uniq.setdefault((i.get("num"), i.get("cls"), i.get("sub"), i.get("proto")), i)
    dev["interfaces"] = list(uniq.values())
    if d:
        dev["addr"]       = addr_of(d)
        dev["bus"]        = _attr(d, "busnum")
        dev["devnum"]     = _attr(d, "devnum")
        dev["id"]         = "%s:%s" % (_attr(d, "idVendor"), _attr(d, "idProduct"))
        dev["speed"]      = _attr(d, "speed")
        dev["authorized"] = _attr(d, "authorized")
        dev["maxchild"]   = _attr(d, "maxchild")
        drivers = []
        for i in glob.glob(os.path.join(d, "*:*")):
            drv = os.path.join(i, "driver")
            if os.path.exists(drv): drivers.append(os.path.basename(os.path.realpath(drv)))
        dev["drivers"] = sorted(set(drivers))
        # Readable while the gate is shut: all of this is populated at enumeration,
        # before anything binds.
        dev["bcd_device"]   = _attr(d, "bcdDevice")     # device/firmware revision
        dev["removable"]    = _attr(d, "removable")     # internal vs plugged in
        dev["quirks"]       = _attr(d, "quirks")        # kernel workarounds for it
        dev["n_interfaces"] = _attr(d, "bNumInterfaces")

    return dev

_i = rules.to_int


def threats(dev):
    """Delegates to the portable core. See airlock/rules.py."""
    return rules.assess(dev)
