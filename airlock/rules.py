"""Portable analysis core: tables and rules, no I/O of any kind.

This module deliberately imports NOTHING and touches no filesystem, no subprocess and
no OS interface. Everything here is a lookup table or a pure function over plain data.

That is on purpose. The Linux host tooling around it will never run on a
microcontroller, but this part is the actual knowledge: which USB class numbers mean
what, which combinations of claims are dangerous, and how a HID boot report becomes
text. An inline RP2040 build reimplements the plumbing and transliterates these tables,
so they are kept free of anything that would not survive the trip to C.

Rules of the house for this file:
  - no imports
  - no I/O
  - tables as flat data, so they can be code-generated into C arrays
  - functions take dicts and return values, never read the world
"""

# --- USB class codes ---------------------------------------------------------
CLASSES = {
    0x00: "per-interface", 0x01: "audio",        0x02: "comms/CDC",  0x03: "HID",
    0x05: "physical",      0x06: "image",        0x07: "printer",    0x08: "mass storage",
    0x09: "hub",           0x0a: "CDC-data",     0x0b: "smartcard",  0x0d: "content-security",
    0x0e: "video",         0x0f: "healthcare",   0x10: "audio/video",0x11: "billboard",
    0x12: "USB-C bridge",  0xdc: "diagnostic",   0xe0: "wireless",   0xef: "misc",
    0xfe: "app-specific",  0xff: "vendor-specific",
}

# --- devices worth naming on sight -------------------------------------------
KNOWN = {
    "303a:1001": "Espressif native USB Serial/JTAG",
    "303a:0002": "ESP32-S2 native USB",
    "1a86:7523": "CH340 serial bridge",
    "1a86:55d4": "CH9102 serial bridge",
    "10c4:ea60": "CP2102 serial bridge",
    "0403:6001": "FT232 serial bridge",
    "2e8a:0003": "RP2040/RP2350 BOOTSEL",
    "2e8a:000a": "RP2040 CDC",
    "2e8a:000c": "Raspberry Pi debugprobe",
    "0483:df11": "STM32 DFU",
    "0483:3748": "ST-Link v2",
    "0483:374b": "ST-Link v2.1",
    "0d28:0204": "DAPLink",
    "1366:0101": "SEGGER J-Link",
}

# --- HID boot keyboard usage IDs ---------------------------------------------
# byte 0 modifiers, byte 1 reserved, bytes 2..7 up to six keycodes
HID_BASE = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"): HID_BASE[4 + _i] = _c
for _i, _c in enumerate("1234567890"):                 HID_BASE[30 + _i] = _c
HID_BASE.update({40:"\n", 41:"<ESC>", 42:"<BKSP>", 43:"\t", 44:" ", 45:"-", 46:"=",
                 47:"[", 48:"]", 49:"\\", 51:";", 52:"'", 53:"`", 54:",", 55:".",
                 56:"/", 57:"<CAPS>", 70:"<PRTSC>", 71:"<SCRLK>", 72:"<PAUSE>",
                 73:"<INS>", 74:"<HOME>", 75:"<PGUP>", 76:"<DEL>", 77:"<END>",
                 78:"<PGDN>", 79:"<RIGHT>", 80:"<LEFT>", 81:"<DOWN>", 82:"<UP>"})
for _i in range(58, 70): HID_BASE[_i] = "<F%d>" % (_i - 57)

_CHORD_NAMES = {"\n": "ENTER", "\t": "TAB", " ": "SPACE"}

HID_SHIFTED = {}
for _i, _c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"): HID_SHIFTED[4 + _i] = _c
for _i, _c in enumerate("!@#$%^&*()"):                 HID_SHIFTED[30 + _i] = _c
HID_SHIFTED.update({45:"_", 46:"+", 47:"{", 48:"}", 49:"|", 51:":", 52:'"',
                    53:"~", 54:"<", 55:">", 56:"?"})

MODIFIERS = ((0x01,"CTRL"), (0x02,"SHIFT"), (0x04,"ALT"), (0x08,"GUI"),
             (0x10,"CTRL"), (0x20,"SHIFT"), (0x40,"ALT"), (0x80,"GUI"))

# --- helpers -----------------------------------------------------------------
def to_int(v, default=0):
    """lsusb prints class/subclass/protocol as decimal strings; sysfs uses hex."""
    if v is None: return default
    s = str(v).strip()
    if not s: return default
    try:
        return int(s, 16) if not s.isdigit() else int(s)
    except ValueError:
        return default

def report_is_prefixed(report):
    """Does this report start with a report ID rather than the modifier byte?

    A boot-protocol keyboard report is 8 bytes: [modifiers][reserved][6 keycodes]. A
    device that declares Report ID items prefixes every report with the ID, shifting
    everything by one: [id][modifiers][reserved][keycodes].

    Getting this wrong is not subtle, and a Flipper Zero running BadUSB demonstrated it
    on 2026-08-23. Its reports are 16 bytes and begin with report ID 0x01, so byte 0 was
    read as the modifier bitmap, whose bit 0 is LCTRL. Every keystroke of the payload
    came out as CTRL+something:

        CHORD  146d:c529  CTRL+p
        CHORD  146d:c529  CTRL+o
        CHORD  146d:c529  CTRL+w      ...spelling "powershell" in chords

    The letters were right, because report[2:8] still landed on real keycodes once the
    zero reserved byte was filtered. Only the modifiers were fiction -- and modifiers are
    the part that matters, since GUI+r is what opens the box.

    The tell is structural. In the boot layout byte 1 is RESERVED and always zero. In the
    prefixed layout byte 2 is the reserved one, and byte 0 is a small constant ID. So a
    report whose byte 1 is non-zero while byte 2 is zero cannot be a boot report, and a
    longer-than-boot report whose first byte is a plausible ID is prefixed.
    """
    if len(report) <= 8:
        return False
    if report[1] and not report[2]:          # byte 1 carries modifiers, byte 2 reserved
        return True
    return 0 < report[0] <= 0x0F and not report[2]


def decode_hid_report(report, previous, prefixed=None):
    """(text, chords, keys_now) from one boot-protocol keyboard report.

    `previous` is the keycode set from the last report, so a held key does not repeat.
    `prefixed` forces the report-ID interpretation; None auto-detects. See
    report_is_prefixed() for why this exists.
    """
    if len(report) < 8: return "", [], set()
    off = report_is_prefixed(report) if prefixed is None else bool(prefixed)
    if off and len(report) < 9: return "", [], set()
    base = 1 if off else 0
    mod = report[base]
    keys = set(k for k in report[base + 2:base + 8] if k)
    fresh = keys - previous
    shift = bool(mod & 0x22)
    names = set(n for bit, n in MODIFIERS if mod & bit)
    others = names - set(["SHIFT"])
    text, chords = "", []
    for k in sorted(fresh):
        ch = (HID_SHIFTED.get(k) if shift else None) or HID_BASE.get(k, "<%d>" % k)
        if others:
            # ENTER, TAB and space are whitespace in `text`, which is what you want when
            # reading typed prose. In a chord they vanish: ch.strip() empties them and
            # ALT+TAB printed as "ALT+". That hid the single most interesting chord a
            # hostile keyboard sends, so name them rather than stripping them away.
            chords.append("+".join(sorted(others)) + "+" + (ch.strip() or _CHORD_NAMES.get(ch, "?")))
        else:
            text += ch
    return text, chords, keys

# ---------------------------------------------------------------- raw descriptors
#
# /sys/bus/usb/devices/*/descriptors is the device descriptor followed by every
# configuration descriptor, exactly as the device sent them. Parsing it directly removes
# the last external dependency: lsusb is a text scrape of the same bytes, and a triage
# box is precisely the machine that will not have usbutils installed.
#
# Every descriptor is length-prefixed -- bLength, bDescriptorType, payload -- so the walk
# is the same shape as the HID report parser: read a length, dispatch on a type, advance.
# Unknown types are skipped by their own length rather than aborting the walk, which is
# what lets class-specific descriptors (audio, CDC, HID) pass through harmlessly.

DESC_DEVICE, DESC_CONFIG, DESC_STRING = 0x01, 0x02, 0x03
DESC_INTERFACE, DESC_ENDPOINT = 0x04, 0x05
DESC_IFACE_ASSOC, DESC_HID, DESC_SS_EP_COMP = 0x0B, 0x21, 0x30

EP_TYPES = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}

# Names for every descriptor type that turns up in a configuration blob. lsusb -v prints
# these raw when it does not recognise them; naming them is most of the value.
DESC_NAMES = {
    0x01: "device", 0x02: "configuration", 0x03: "string", 0x04: "interface",
    0x05: "endpoint", 0x06: "device qualifier", 0x07: "other-speed configuration",
    0x08: "interface power", 0x09: "OTG", 0x0A: "debug",
    0x0B: "interface association", 0x0F: "BOS", 0x10: "device capability",
    0x21: "HID", 0x22: "HID report", 0x23: "HID physical",
    0x24: "class-specific interface", 0x25: "class-specific endpoint",
    0x29: "hub", 0x2A: "SuperSpeed hub", 0x30: "SuperSpeed endpoint companion",
    0x31: "SuperSpeedPlus isochronous companion",
}


def descriptor_name(t):
    return DESC_NAMES.get(t, "unknown 0x%02x" % t)


def _u16(b, i):
    return b[i] | (b[i + 1] << 8)


def parse_descriptors(blob):
    """Structure of a device, straight from its own descriptor bytes.

    Returns the same shape `descriptors()` built from lsusb, plus endpoint detail lsusb's
    text output made awkward to get: transfer type, max packet size, interval, and
    alternate settings kept distinct instead of collapsed.

    Never raises. A device controls these bytes, and a truncated or malformed blob is
    exactly what a hostile one would send; the walk stops and reports what it got.
    """
    out = {"interfaces": [], "configs": [], "truncated": False,
           "total_bytes": 0, "parsed_bytes": 0, "descriptor_count": 0}
    if not blob:
        return out
    b = bytes(blob)
    n = len(b)
    out["total_bytes"] = n
    i = 0
    cur_cfg = None
    while i < n:
        if i + 2 > n:
            out["truncated"] = True
            break
        ln, typ = b[i], b[i + 1]
        # A zero length would not advance, and a length past the end is a lie. Either
        # way the rest is unreadable; stop rather than loop or guess.
        if ln < 2 or i + ln > n:
            out["truncated"] = True
            break
        d = b[i:i + ln]

        if typ == DESC_DEVICE and ln >= 18:
            out["usb_version"] = "%x.%02x" % (d[3], d[2])
            out["dev_class"] = str(d[4])
            out["dev_sub"] = str(d[5])
            out["dev_proto"] = str(d[6])
            out["ep0_size"] = str(d[7])
            out["id"] = "%04x:%04x" % (_u16(d, 8), _u16(d, 10))
            out["bcd_device"] = "%04x" % _u16(d, 12)
            out["n_configs"] = str(d[17])
        elif typ == DESC_CONFIG and ln >= 9:
            # bMaxPower is in 2mA units, except at SuperSpeed where it is 8mA.
            ss = str(out.get("usb_version", "")).startswith("3")
            cur_cfg = {
                "value": str(d[5]),
                "n_interfaces": str(d[4]),
                "cfg_attrs": "%02x" % d[7],
                "max_power": "%dmA" % (d[8] * (8 if ss else 2)),
            }
            out["configs"].append(cur_cfg)
        elif typ == DESC_INTERFACE and ln >= 9:
            out["interfaces"].append({
                "num": str(d[2]),
                "alt": str(d[3]),
                "n_eps": str(d[4]),
                "cls": str(d[5]),
                "sub": str(d[6]),
                "proto": str(d[7]),
                "eps": [],
                "config": (cur_cfg or {}).get("value"),
            })
        elif typ == DESC_IFACE_ASSOC and ln >= 8:
            # Groups several interfaces into one logical function: a webcam's control
            # and streaming interfaces, a headset's audio in and out. Without it a
            # multi-function device reads as several unrelated things.
            out.setdefault("associations", []).append({
                "first": str(d[2]), "count": str(d[3]),
                "cls": str(d[4]), "sub": str(d[5]), "proto": str(d[6]),
            })
        elif typ == DESC_ENDPOINT and ln >= 7:
            if out["interfaces"]:
                out["interfaces"][-1]["eps"].append({
                    "addr": "0x%02x" % d[2],
                    "dir": "IN" if d[2] & 0x80 else "OUT",
                    "num": str(d[2] & 0x0F),
                    "type": EP_TYPES.get(d[3] & 0x03, "?"),
                    "max_packet": str(_u16(d, 4) & 0x07FF),
                    "interval": str(d[6]),
                })
        else:
            # Everything else is kept rather than dropped: class-specific descriptors
            # carry the actual shape of an audio or CDC function, and a HID descriptor
            # names the report descriptor's length. Recording what was there, and where,
            # is what lets --verbose account for every byte of the blob.
            rec = {"type": typ, "name": descriptor_name(typ), "len": ln, "at": i,
                   "raw": d.hex()}
            if out["interfaces"]:
                out["interfaces"][-1].setdefault("extra", []).append(rec)
            else:
                out.setdefault("extra", []).append(rec)
        out["parsed_bytes"] += ln
        out["descriptor_count"] += 1
        i += ln

    # The first configuration is the one reported at the top level, matching what the
    # kernel exposes in sysfs and what lsusb prints without --verbose.
    if out["configs"]:
        out.setdefault("cfg_attrs", out["configs"][0]["cfg_attrs"])
        out.setdefault("max_power", out["configs"][0]["max_power"])
        out.setdefault("n_interfaces", out["configs"][0]["n_interfaces"])
    return out


# ---------------------------------------------------------------- report descriptors
#
# A HID report descriptor is the device's own declaration of what it can SEND. The class
# code says "I am a HID"; this says "and these are the kinds of report I will produce".
# That difference is the whole BadUSB question. A keyboard that also declares consumer
# control and a vendor-defined channel is not a keyboard with extras, it is a device
# that has told you it intends to do more than type.
#
# Format: a flat stream of items. Each short item is a prefix byte
#
#     bTag(4) | bType(2) | bSize(2)
#
# followed by 0, 1, 2 or 4 data bytes (bSize 3 means 4). bType: 0 Main, 1 Global,
# 2 Local. We track the current Usage Page (global) and the pending Usages (local), and
# every time a Main:Input item appears we record what was declared. That is far short of
# a full HID parser -- no field layout, no logical ranges -- and it is all the security
# question needs.

USAGE_PAGES = {
    0x01: "generic desktop", 0x02: "simulation", 0x03: "vr", 0x04: "sport",
    0x05: "game", 0x06: "generic device", 0x07: "keyboard", 0x08: "LED",
    0x09: "button", 0x0A: "ordinal", 0x0B: "telephony", 0x0C: "consumer",
    0x0D: "digitizer", 0x0F: "PID", 0x10: "unicode", 0x14: "alphanumeric display",
    # Outside the standard block but universally allocated in practice. Naming these
    # turns "unknown page 0xf1d0" into "this is a security key", which is the difference
    # between a reader investigating and a reader shrugging.
    0xF1D0: "FIDO alliance", 0xFF00: "vendor-defined",
}

# The standard pages stop at 0x14 with a few gaps. Everything from 0x92 up is either
# reserved-and-unassigned or explicitly vendor-defined, and BOTH mean "no standard
# semantics, the device decides what these bytes are". Treating only 0xFF00+ as
# non-standard missed 0xF1D0 entirely -- a YubiKey's 64-byte bidirectional FIDO pipe was
# not flagged as a channel at all on 2026-08-23, and an attacker can pick any of the
# thousands of unassigned pages below 0xFF00 to get the same silence.
def nonstandard_page(page):
    # Being NAMEABLE is not the same as being standard. Adding 0xF1D0 to the table above
    # so it prints nicely immediately made this return False for it, which would have
    # un-flagged the very device that exposed the gap. Standard HID usage pages all live
    # below 0x92; everything at or above that is the device's own territory whether or
    # not this program happens to know a name for it.
    return page is not None and page >= 0x92

# Generic-desktop usages worth naming, because "generic desktop" alone says nothing.
DESKTOP_USAGE = {0x01: "pointer", 0x02: "mouse", 0x04: "joystick", 0x05: "gamepad",
                 0x06: "keyboard", 0x07: "keypad", 0x80: "system control"}


def page_name(page):
    if page is None:
        return "?"
    known = USAGE_PAGES.get(page)
    if known and page >= 0x92:
        return "%s (0x%04x)" % (known, page)
    if known:
        return known
    if 0xFF00 <= page <= 0xFFFF:
        return "vendor-defined 0x%04x" % page
    if nonstandard_page(page):
        return "unassigned 0x%04x" % page
    return "0x%04x" % page


def parse_report_descriptor(data):
    """What Input reports this descriptor declares.

    Returns {"inputs": [{"page": int, "page_name": str, "usages": [int],
                         "names": [str], "report_id": int|None}, ...],
             "pages": sorted set of pages with Input reports,
             "truncated": bool}

    Never raises on malformed input: a hostile device is exactly the thing that sends a
    truncated or nonsense descriptor, and refusing to report anything would hand it the
    outcome it wanted. Anything unparseable ends the walk and sets truncated.
    """
    out = {"inputs": [], "outputs": [], "features": [],
           "pages": [], "collections": [], "truncated": False}
    if not data:
        return out
    b = bytes(data)
    i, page, usages, report_id = 0, None, [], None
    n = len(b)
    while i < n:
        prefix = b[i]
        i += 1
        if prefix == 0xFE:                 # long item: 1 size byte, 1 tag, then data
            if i + 1 >= n:
                out["truncated"] = True; break
            i += 2 + b[i]
            continue
        size = prefix & 0x03
        size = 4 if size == 3 else size
        if i + size > n:
            out["truncated"] = True; break
        val = int.from_bytes(b[i:i + size], "little") if size else 0
        i += size
        tag, typ = (prefix >> 4) & 0x0F, (prefix >> 2) & 0x03

        if typ == 1:                       # Global
            if tag == 0x0:   page = val
            elif tag == 0x8: report_id = val
        elif typ == 2:                     # Local
            if tag == 0x0:                 # Usage
                usages.append(val)
            elif tag in (0x1, 0x2):        # Usage Minimum / Maximum
                usages.append(val)
        elif typ == 0:                     # Main
            if tag == 0xA and usages:      # Collection
                # Per spec the pending Usage describes the collection, and that is
                # where "this is a mouse" actually lives -- an Input item inside it
                # carries X/Y, not the word mouse. Record it before it is cleared.
                out["collections"].append({"page": page, "usage": usages[0]})
            if tag in (0x8, 0x9, 0xB):     # Input / Output / Feature
                seen = sorted(set(usages))
                bucket = {0x8: "inputs", 0x9: "outputs", 0xB: "features"}[tag]
                out[bucket].append({
                    "page": page,
                    "page_name": page_name(page),
                    "usages": seen,
                    "names": [DESKTOP_USAGE[u] for u in seen
                              if page == 0x01 and u in DESKTOP_USAGE],
                    "report_id": report_id,
                })
            # Main items clear the local state whatever they were
            usages = []
    # Pages from EVERY direction. A vendor page that appears only in an Output item is
    # still a channel, and keying this off inputs alone hid exactly that case.
    out["pages"] = sorted({d["page"] for k in ("inputs", "outputs", "features")
                           for d in out[k] if d["page"] is not None})
    return out


def describe_capability(parsed):
    """One human line per distinct declared capability."""
    if not parsed:
        return []
    seen, lines = set(), []
    for c in parsed.get("collections", []):
        if c["page"] == 0x01 and c["usage"] in DESKTOP_USAGE:
            nm = DESKTOP_USAGE[c["usage"]]
            if nm not in seen:
                seen.add(nm); lines.append(nm)
    if not parsed.get("inputs"):
        return lines
    for d in parsed["inputs"]:
        label = d["page_name"]
        if d["names"]:
            label += " (" + ", ".join(d["names"]) + ")"
        if label not in seen:
            seen.add(label)
            lines.append(label)
    return lines


def capability_threats(parsed):
    """(level, headline, detail) for what a descriptor DECLARES it can send.

    The class code is a claim about category. This is a claim about capability, and it
    is the device's own words. A keyboard page plus a consumer page plus a vendor page
    is not three features, it is a device that can type, press media keys and open an
    arbitrary channel.
    """
    if not parsed:
        return []
    out = []
    if parsed.get("truncated"):
        # Report this even when nothing else parsed. A device controls its own
        # descriptor; one that does not decode is a choice, and bailing out early meant
        # the most suspicious descriptors produced the quietest output.
        out.append(("MED", "report descriptor is malformed or truncated",
                    "a device controls its own descriptor, and a broken one is a choice"))
    if not parsed.get("inputs"):
        return out
    pages = set(parsed["pages"])
    desktop = {u for d in parsed["inputs"] if d["page"] == 0x01 for u in d["usages"]}
    desktop |= {c["usage"] for c in parsed.get("collections", []) if c["page"] == 0x01}

    types = set()
    if 0x07 in pages or 0x06 in desktop: types.add("keyboard")
    if 0x02 in desktop or 0x01 in desktop: types.add("pointer")
    if 0x0C in pages: types.add("consumer control")
    # Every page the device decides the meaning of, not just the 0xFF00 block. See
    # nonstandard_page(): keying this to 0xFF00+ missed 0xF1D0 and every other
    # unassigned page an attacker is free to pick.
    vendor = sorted(p for p in pages if nonstandard_page(p))
    if vendor: types.add("vendor-defined channel")

    # Direction. An Output or Feature item on one of those pages is a HOST-TO-DEVICE
    # path with no defined semantics -- the shape of command and control, and the half
    # the parser did not even read until a YubiKey's 64-byte bidirectional FIDO pipe
    # went through here reported as nothing at all.
    back = sorted({d["page"] for k in ("outputs", "features")
                   for d in parsed.get(k, []) if nonstandard_page(d.get("page"))})

    if "keyboard" in types and len(types) > 1:
        others = sorted(types - {"keyboard"})
        out.append(("HIGH", "declares keyboard AND " + ", ".join(others),
                    "its own report descriptor says it can type and " +
                    ", ".join(others) + ". A keyboard has no reason to."))
    elif "keyboard" in types:
        out.append(("HIGH", "report descriptor declares keyboard input",
                    "not merely a HID class claim: it declares the reports"))
    if vendor:
        out.append(("MED", "declares a vendor-defined channel (%s)" %
                    ", ".join(page_name(p) for p in vendor),
                    "opaque by design; the class code does not describe it"))
    if back:
        out.append(("MED", "that channel is bidirectional (%s)" %
                    ", ".join(page_name(p) for p in back),
                    "declares host-to-device reports on a page with no standard "
                    "meaning"))
    return out


def assess(device):
    """[(level, headline, why)] from a parsed device dict. Pure.

    device = {"interfaces":[{"cls","sub","proto"}...], "n_configs":str,
              "max_power":str, "authorized":str}
    """
    out = []
    ifs = device.get("interfaces") or []
    classes = set(to_int(i.get("cls")) for i in ifs)

    if 0x03 in classes and 0x08 in classes:
        out.append(("HIGH", "claims HID and mass storage together",
                    "the classic BadUSB shape: looks like a drive, can also type"))
    for i in ifs:
        if to_int(i.get("cls")) != 0x03: continue
        proto = str(i.get("proto") or "0")
        if proto == "1":
            out.append(("HIGH", "claims a boot-protocol KEYBOARD",
                        "on bind it can inject keystrokes into your session immediately"))
        elif proto == "2":
            out.append(("MED", "claims a boot-protocol mouse",
                        "pointer injection, and a common cover for a second HID interface"))
        else:
            # If a report descriptor was fetched for this interface, say what the device
            # DECLARED instead of admitting we did not look. The old line named the
            # evidence it lacked; capture.report_descriptor() gets it over ep0, on an
            # interface no driver is allowed to bind.
            rd = (device.get("report_descriptors") or {}).get(str(i.get("num")))
            parsed = parse_report_descriptor(rd) if rd else None
            caps = capability_threats(parsed) if parsed else []
            if caps:
                out.extend(caps)
            elif parsed:
                # A descriptor was read and nothing in it is alarming. Say WHAT it is
                # rather than reporting silence: "declares volume and transport keys" is
                # an answer, "nothing to report" reads like the tool did not look.
                what = describe_capability(parsed)
                out.append(("LOW", "report descriptor declares " +
                            (", ".join(what) if what else "no input reports"),
                            "read directly from the device; no keyboard and no "
                            "vendor-defined channel among them"))
            else:
                out.append(("MED", "claims a raw HID interface",
                            "no boot protocol, so intent is opaque without its report "
                            "descriptor"))
    if to_int(device.get("n_configs"), 1) > 1:
        out.append(("MED", "advertises %s configurations" % device.get("n_configs"),
                    "can present one identity, then switch to another"))
    if 0x03 in classes and (0x02 in classes or 0x0a in classes):
        out.append(("MED", "HID alongside a serial interface",
                    "legitimate for some debug probes; suspicious on a plain USB-serial adapter"))
    # 0xe0 covers Bluetooth AND RNDIS. Only RNDIS is a takeover risk, and flagging every
    # Bluetooth radio teaches the operator to ignore the tool.
    for i in ifs:
        c, sub, proto = to_int(i.get("cls")), str(i.get("sub") or ""), str(i.get("proto") or "")
        if c == 0xe0 and sub == "1" and proto == "3":
            out.append(("MED", "claims RNDIS (a network adapter)",
                        "can take over DNS and routing the moment it binds"))
        elif c == 0x02 and sub in ("6", "13"):
            out.append(("MED", "claims a CDC ethernet interface",
                        "can take over DNS and routing the moment it binds"))
    if classes == set([0xff]):
        out.append(("LOW", "vendor-specific class only",
                    "descriptors reveal nothing; judge it by behaviour"))
    mp = str(device.get("max_power") or "")
    if mp.endswith("mA"):
        try:
            if int(mp[:-2]) > 500:
                out.append(("LOW", "requests %s" % mp, "above the 500mA USB2 budget"))
        except ValueError:
            pass
    if not ifs:
        out.append(("LOW", "no interface descriptors readable",
                    "device may be unauthorized, or enumeration did not complete"))
    return out

def worst(levels):
    for lvl in ("HIGH", "MED", "LOW"):
        if lvl in levels: return lvl
    return None
