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


def blinds_downstream(addr, authorized, is_hub):
    """Is this an unauthorized HUB, i.e. one that is hiding whatever is behind it.

    This replaces a stranded_by() that walked UP from a device to find a shut hub
    above it. Proven unreachable on real hardware 2026-08-22: a withheld hub binds no
    driver, so nothing behind it ever enumerates, so the children do not exist in
    sysfs to be marked. Plugging a dock holding two devices into a closed gate listed
    the hub alone and the two devices simply vanished from the tree.

    So the warning belongs on the hub, which does exist, and it has to be phrased as
    "you cannot see what is behind this" rather than "these are unreachable" -- the
    tool genuinely does not know what is back there. That is the whole point: an
    unauthorized hub is an opaque surface, and a hostile device can present as one.
    """
    return bool(is_hub) and authorized.get(addr) == "0" and not str(addr).startswith("usb")


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
    """Parse lsusb -v into something structured. Works unprivileged for interfaces.

    Addressed with `lsusb -s BUS:DEV` rather than `-d VID:PID` whenever the device
    can be located. `-d` matches on model, so two identical devices dump one after
    the other into the same text and the parse silently merges them.
    """
    d = sysfs_for(spec)
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

        # Fetch the report descriptor for any HID interface no driver is holding.
        #
        # Deliberately narrow. It is a real control transfer to the device, so it runs
        # only when it can actually succeed and only when it tells us something we do
        # not already know:
        #   - HID class, and NOT boot protocol. A boot keyboard has already declared
        #     itself; the descriptor adds nothing to that verdict.
        #   - no driver bound, because the kernel returns EBUSY for a control transfer
        #     aimed at an interface a driver owns. That is exactly the state the airlock
        #     creates, so this reads a held device and refuses to bother a working one.
        #   - root, since it needs the usbfs node.
        rds = {}
        for i in sorted(glob.glob(os.path.join(d, "*:*"))):
            try:
                if _attr(i, "bInterfaceClass") != "03":              continue
                if _attr(i, "bInterfaceProtocol") in ("01", "02"):   continue
                if os.path.exists(os.path.join(i, "driver")):        continue
                num = _attr(i, "bInterfaceNumber")
                if num is None:                                      continue
                from . import capture as _cap
                raw = _cap.report_descriptor(spec, int(num, 16) if
                                             not str(num).isdigit() else int(num))
                if raw:
                    rds[str(int(num, 16) if not str(num).isdigit() else int(num))] = raw
            except Exception:
                continue          # a device that will not answer is a fact, not a fault
        if rds:
            dev["report_descriptors"] = rds
    return dev

_i = rules.to_int


def threats(dev):
    """Delegates to the portable core. See airlock/rules.py."""
    return rules.assess(dev)
