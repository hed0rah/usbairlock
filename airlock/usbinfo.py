"""Read what a USB device says about itself, and judge the claims.

Everything a USB device reports is self-asserted. There is no authentication anywhere
in the protocol. Treat every field as a claim.
"""
import glob, os, re, subprocess
from . import rules

CLASSES = rules.CLASSES
KNOWN = rules.KNOWN

def sh(c, t=20):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t).stdout
    except Exception: return ""

def have_lsusb():
    return bool(sh("command -v lsusb").strip())

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
        product = _attr(d, "product") or ""
        vendor  = _attr(d, "manufacturer") or ""
        name = (f"{vendor} {product}".strip()) or ""
        out[f"{int(busnum):03d}/{int(devnum):03d}" if busnum.isdigit() and devnum.isdigit()
            else base] = {
            "bus": busnum, "dev": devnum, "id": f"{vid}:{pid}",
            "name": name, "sysfs": d, "is_hub": is_hub,
                "authorized": _attr(d, "authorized"),
        }
    return out

def sysfs_for(vid_pid):
    v, p = vid_pid.split(":")
    for d in glob.glob("/sys/bus/usb/devices/*/"):
        try:
            if open(d+"idVendor").read().strip()==v and open(d+"idProduct").read().strip()==p:
                return d
        except Exception: pass
    return None

def _attr(d, name):
    try: return open(os.path.join(d, name)).read().strip()
    except Exception: return None

def descriptors(vid_pid):
    """Parse lsusb -v into something structured. Works unprivileged for interfaces."""
    txt = sh(f"lsusb -v -d {vid_pid} 2>/dev/null", 25)
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
        if m: dev[key] = m.group(1).strip()
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
                if len(parts) > 2: cur["name"] = parts[2]
    if cur: ifs.append(cur)
    # collapse alternate settings: same interface number repeats per bandwidth variant
    uniq = {}
    for i in ifs:
        uniq.setdefault((i.get("num"), i.get("cls"), i.get("sub"), i.get("proto")), i)
    dev["interfaces"] = list(uniq.values())
    d = sysfs_for(vid_pid)
    if d:
        dev["speed"]      = _attr(d, "speed")
        dev["authorized"] = _attr(d, "authorized")
        dev["maxchild"]   = _attr(d, "maxchild")
        drivers = []
        for i in glob.glob(os.path.join(d, "*:*")):
            drv = os.path.join(i, "driver")
            if os.path.exists(drv): drivers.append(os.path.basename(os.path.realpath(drv)))
        dev["drivers"] = sorted(set(drivers))
    return dev

_i = rules.to_int


def threats(dev):
    """Delegates to the portable core. See airlock/rules.py."""
    return rules.assess(dev)
