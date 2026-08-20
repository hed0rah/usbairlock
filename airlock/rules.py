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
            chords.append("+".join(sorted(others)) + "+" + ch.strip())
        else:
            text += ch
    return text, chords, keys

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
            out.append(("MED", "claims a raw HID interface",
                        "no boot protocol, so intent is opaque without its report descriptor"))
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
