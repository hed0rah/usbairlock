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

def decode_hid_report(report, previous):
    """(text, chords, keys_now) from one 8-byte boot-protocol report.

    `previous` is the keycode set from the last report, so a held key does not repeat.
    """
    if len(report) < 8: return "", [], set()
    mod = report[0]
    keys = set(k for k in report[2:8] if k)
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
}

# Generic-desktop usages worth naming, because "generic desktop" alone says nothing.
DESKTOP_USAGE = {0x01: "pointer", 0x02: "mouse", 0x04: "joystick", 0x05: "gamepad",
                 0x06: "keyboard", 0x07: "keypad", 0x80: "system control"}


def page_name(page):
    if page is None:
        return "?"
    if 0xFF00 <= page <= 0xFFFF:
        return "vendor-defined 0x%04x" % page
    return USAGE_PAGES.get(page, "0x%04x" % page)


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
    out = {"inputs": [], "pages": [], "collections": [], "truncated": False}
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
            if tag == 0x8:                 # Input
                seen = sorted(set(usages))
                out["inputs"].append({
                    "page": page,
                    "page_name": page_name(page),
                    "usages": seen,
                    "names": [DESKTOP_USAGE[u] for u in seen
                              if page == 0x01 and u in DESKTOP_USAGE],
                    "report_id": report_id,
                })
            # Main items clear the local state whatever they were
            usages = []
    out["pages"] = sorted({d["page"] for d in out["inputs"] if d["page"] is not None})
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
    vendor = sorted(p for p in pages if 0xFF00 <= p <= 0xFFFF)
    if vendor: types.add("vendor-defined channel")

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
                    ", ".join("0x%04x" % p for p in vendor),
                    "opaque by design; the class code does not describe it"))
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
