#!/usr/bin/env python3
"""What a HID device DECLARES it can send, from its own report descriptor.

The class code is a claim about category: "I am a HID". The report descriptor is a claim
about capability: "and these are the reports I will produce". That difference is the
BadUSB question. Until 2026-08-22 the tool said

    [MED] claims a raw HID interface
          no boot protocol, so intent is opaque without its report descriptor

which names the evidence it did not have. It is fetchable with a standard GET_DESCRIPTOR
on endpoint 0 -- no driver, no interface claim -- so it can be read from a device the
airlock is holding with usbhid detached. Full declared capability, zero ability to act.

Pure parsing here: no root, no devices. One real descriptor captured from hardware.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import rules                                    # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


# HID 1.11 spec, Appendix B.1, verbatim. If the parser cannot do this one it can do none.
BOOT_KEYBOARD = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x03,
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02,
    0x95, 0x01, 0x75, 0x03, 0x91, 0x03,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
    0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0])

BOOT_MOUSE = bytes([
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01, 0xA1, 0x00,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x75, 0x01, 0x95, 0x03, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
    0xC0, 0xC0])

# The shape that matters: types, presses media keys, and opens a private channel.
DUCKY = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07,
    0x19, 0xE0, 0x29, 0xE7, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
    0x05, 0x0C, 0x09, 0x01, 0xA1, 0x01,
    0x19, 0x00, 0x2A, 0x9C, 0x02, 0x75, 0x10, 0x95, 0x01, 0x81, 0x00, 0xC0,
    0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01,
    0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0xC0])

# Captured from a real device on 2026-08-22: the HID interface of a USB-C dock's audio
# section. Volume, transport keys, mute, and a telephony hook switch.
DOCK_AUDIO = bytes([
    0x05, 0x0C, 0x09, 0x01, 0xA1, 0x01, 0x15, 0x00, 0x25, 0x01,
    0x09, 0xE9, 0x09, 0xEA, 0x09, 0xB5, 0x09, 0xB6, 0x75, 0x01, 0x95, 0x04, 0x81, 0x02,
    0x09, 0xE2, 0x09, 0xB7, 0x09, 0xCD, 0x95, 0x03, 0x81, 0x06,
    0x05, 0x0B, 0x09, 0x20, 0x95, 0x01, 0x81, 0x06,
    0x05, 0x0C, 0x26, 0xFF, 0x00, 0x09, 0x00, 0x75, 0x08, 0x95, 0x03, 0x81, 0x02,
    0x09, 0x00, 0x95, 0x04, 0x91, 0x02, 0xC0])


def levels(d):
    return [t[0] for t in rules.capability_threats(rules.parse_report_descriptor(d))]


def main():
    print()
    # -- the spec descriptor -----------------------------------------------------
    kb = rules.parse_report_descriptor(BOOT_KEYBOARD)
    check("boot keyboard: keyboard page found", 0x07 in kb["pages"], True)
    check("boot keyboard: not truncated", kb["truncated"], False)
    check("boot keyboard: reads as a keyboard",
          "keyboard" in rules.describe_capability(kb), True)
    check("boot keyboard: HIGH", levels(BOOT_KEYBOARD), ["HIGH"])

    # -- a mouse is not a keyboard -----------------------------------------------
    ms = rules.parse_report_descriptor(BOOT_MOUSE)
    check("mouse names itself from its collection",
          "mouse" in rules.describe_capability(ms), True)
    check("mouse raises nothing", levels(BOOT_MOUSE), [])
    check("mouse declares no keyboard page", 0x07 in ms["pages"], False)

    # -- the shape that matters --------------------------------------------------
    dk = rules.parse_report_descriptor(DUCKY)
    caps = rules.describe_capability(dk)
    check("ducky: all three capabilities seen",
          all(c in " ".join(caps) for c in ("keyboard", "consumer", "vendor")), True)
    thr = rules.capability_threats(dk)
    check("ducky: HIGH", thr[0][0], "HIGH")
    check("ducky: the headline names the combination, not just 'keyboard'",
          "AND" in thr[0][1], True)
    check("ducky: the vendor channel is called out separately",
          any("vendor-defined channel" in t[1] for t in thr), True)

    # A keyboard alone is HIGH, but the COMBINATION must read differently -- that is
    # the whole point of reading the descriptor rather than the class code.
    check("a plain keyboard and a ducky do not get the same headline",
          rules.capability_threats(kb)[0][1] == thr[0][1], False)

    # -- the real device ---------------------------------------------------------
    dock = rules.parse_report_descriptor(DOCK_AUDIO)
    check("real dock HID: consumer page", 0x0C in dock["pages"], True)
    check("real dock HID: telephony page", 0x0B in dock["pages"], True)
    check("real dock HID: no keyboard", 0x07 in dock["pages"], False)
    check("real dock HID: raises nothing", levels(DOCK_AUDIO), [])
    check("real dock HID: but still says what it is",
          sorted(rules.describe_capability(dock)), ["consumer", "telephony"])

    # -- malformed input ---------------------------------------------------------
    # A hostile device is exactly the thing that sends a broken descriptor. Refusing to
    # report anything would hand it the outcome it wanted.
    trunc = rules.parse_report_descriptor(BOOT_KEYBOARD[:7])
    check("truncated: flagged", trunc["truncated"], True)
    check("truncated: reported even with no Input items",
          any("malformed or truncated" in t[1] for t in
              rules.capability_threats(trunc)), True)
    check("truncated: still reports what it managed to read",
          "keyboard" in rules.describe_capability(trunc), True)

    for bad, label in ((b"", "empty"), (b"\xff" * 40, "all 0xff"),
                       (bytes(range(256)), "every byte value"),
                       (b"\xfe", "long-item prefix with no body"),
                       (b"\x05", "item claiming data it does not have")):
        try:
            rules.parse_report_descriptor(bad)
            rules.capability_threats(rules.parse_report_descriptor(bad))
            ok = True
        except Exception as e:
            ok = f"raised {e}"
        check(f"survives {label}", ok, True)

    # -- integration with assess() ----------------------------------------------
    raw_hid = {"interfaces": [{"cls": "3", "sub": "0", "proto": "0", "num": "0"}],
               "n_configs": "1"}
    check("without a descriptor, the old honest MED remains",
          [t[1] for t in rules.assess(raw_hid)], ["claims a raw HID interface"])

    with_desc = dict(raw_hid, report_descriptors={"0": DUCKY})
    got = rules.assess(with_desc)
    check("with one, MED 'intent opaque' is replaced by what it declared",
          any("raw HID interface" in t[1] for t in got), False)
    check("and the verdict becomes HIGH", got[0][0], "HIGH")

    benign = dict(raw_hid, report_descriptors={"0": DOCK_AUDIO})
    gotb = rules.assess(benign)
    check("a benign descriptor still says what it is rather than nothing",
          gotb[0][0], "LOW")
    check("naming the actual capability",
          "consumer" in gotb[0][1], True)

    # a boot keyboard already declared itself; the descriptor must not double-report
    boot = {"interfaces": [{"cls": "3", "sub": "1", "proto": "1", "num": "0"}],
            "n_configs": "1", "report_descriptors": {"0": BOOT_KEYBOARD}}
    check("a boot keyboard is not reported twice",
          len([t for t in rules.assess(boot) if "keyboard" in t[1].lower()]), 1)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
