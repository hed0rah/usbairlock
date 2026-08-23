#!/usr/bin/env python3
"""Parsing the raw descriptor blob, which is what replaced lsusb.

/sys/bus/usb/devices/*/descriptors is the device descriptor followed by every
configuration descriptor, exactly as the device sent them. lsusb is a text scrape of the
same bytes, and a triage box is precisely the machine without usbutils installed.

Parsing them directly is also more accurate: the scrape collapsed alternate settings, so
an audio interface whose endpoints live on alt 1 appeared to have none.

Pure parsing. No root, no devices. Two blobs captured from real hardware.
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


# Minimal, hand-built, exercising the shapes the walker must not trip on.
MINIMAL_DEVICE = bytes([
    18, 0x01, 0x10, 0x01, 0x00, 0x00, 0x00, 64,
    0x2c, 0x0c, 0x23, 0x2d, 0x00, 0x01, 1, 2, 3, 1])


def main():
    print()
    # -- the device descriptor ---------------------------------------------------
    d = rules.parse_descriptors(MINIMAL_DEVICE)
    check("vendor and product decode little-endian", d["id"], "0c2c:2d23")
    check("bcdUSB decodes as a version", d["usb_version"], "1.10")
    check("bcdDevice decodes", d["bcd_device"], "0100")
    check("ep0 max packet", d["ep0_size"], "64")
    check("configuration count", d["n_configs"], "1")
    check("nothing truncated", d["truncated"], False)
    check("every byte parsed", (d["parsed_bytes"], d["total_bytes"]), (18, 18))

    # -- malformed input ---------------------------------------------------------
    # A device controls these bytes. A blob that does not decode is what a hostile one
    # would send, so the walk must stop and say so rather than raise or loop.
    for bad, label in (
            (b"", "empty"),
            (b"\x00\x01", "zero length would not advance"),
            (b"\xff\x01", "length past the end"),
            (b"\x12", "one byte"),
            (MINIMAL_DEVICE[:9], "device descriptor cut in half"),
            (b"\x04\x05\x06", "length shorter than the header implies"),
            (bytes(range(256)), "arbitrary bytes"),
            (b"\x02\x02\x00\x00", "config with an impossible total length")):
        try:
            r = rules.parse_descriptors(bad)
            ok = isinstance(r, dict)
        except Exception as e:
            ok = f"raised {e}"
        check(f"survives {label}", ok, True)

    check("a zero length is reported as truncated, not looped on",
          rules.parse_descriptors(b"\x00\x01")["truncated"], True)
    check("a length past the end is reported as truncated",
          rules.parse_descriptors(b"\xff\x01")["truncated"], True)
    check("a truncated blob still reports what it read",
          rules.parse_descriptors(MINIMAL_DEVICE + b"\xff\x02")["id"], "0c2c:2d23")

    # -- descriptor naming --------------------------------------------------------
    check("interface association is named", rules.descriptor_name(0x0B),
          "interface association")
    check("HID is named", rules.descriptor_name(0x21), "HID")
    check("class-specific interface is named", rules.descriptor_name(0x24),
          "class-specific interface")
    check("an unknown type is reported as its number, not dropped",
          rules.descriptor_name(0x77), "unknown 0x77")

    # -- accounting ---------------------------------------------------------------
    # The point of the byte count: lsusb silently skips what it does not recognise.
    # Being able to say "all of it" is the claim, so it has to be true.
    r = rules.parse_descriptors(MINIMAL_DEVICE)
    check("descriptor count", r["descriptor_count"], 1)
    padded = MINIMAL_DEVICE + bytes([4, 0x77, 0, 0])       # an unknown 4-byte descriptor
    r2 = rules.parse_descriptors(padded)
    check("an unknown descriptor is still counted, not skipped",
          (r2["parsed_bytes"], r2["total_bytes"]), (22, 22))
    check("and it is kept rather than dropped",
          (r2.get("extra") or [{}])[0].get("name"), "unknown 0x77")

    # -- endpoints ----------------------------------------------------------------
    # bEndpointAddress bit 7 is direction; bmAttributes low two bits are the type.
    blob = MINIMAL_DEVICE + bytes([
        9, 0x02, 25, 0, 1, 1, 0, 0x80, 50,
        9, 0x04, 0, 0, 1, 3, 0, 0, 0,
        7, 0x05, 0x83, 0x03, 8, 0, 10])
    e = rules.parse_descriptors(blob)
    check("interface parsed", len(e["interfaces"]), 1)
    ep = e["interfaces"][0]["eps"][0]
    check("endpoint direction from bit 7", ep["dir"], "IN")
    check("endpoint number from the low nibble", ep["num"], "3")
    check("transfer type from bmAttributes", ep["type"], "interrupt")
    check("max packet is the low 11 bits", ep["max_packet"], "8")
    check("interval", ep["interval"], "10")
    check("config power is in 2mA units", e["configs"][0]["max_power"], "100mA")
    check("config attrs preserved as hex", e["configs"][0]["cfg_attrs"], "80")

    # SuperSpeed reports bMaxPower in 8mA units, not 2mA. Getting this wrong
    # under-reports a USB3 device's draw by a factor of four.
    ss = bytes([18, 0x01, 0x00, 0x03, 0, 0, 0, 9, 0x2c, 0x0c, 0x23, 0x2d,
                0, 1, 1, 2, 3, 1]) + bytes([9, 0x02, 9, 0, 1, 1, 0, 0x80, 50])
    check("SuperSpeed power is in 8mA units",
          rules.parse_descriptors(ss)["configs"][0]["max_power"], "400mA")

    # -- alternate settings, the thing the lsusb scrape lost ----------------------
    alts = MINIMAL_DEVICE + bytes([
        9, 0x02, 27, 0, 1, 1, 0, 0x80, 50,
        9, 0x04, 1, 0, 0, 1, 2, 0, 0,          # if1 alt0, no endpoints
        9, 0x04, 1, 1, 1, 1, 2, 0, 0,          # if1 alt1, one endpoint
        7, 0x05, 0x01, 0x01, 200, 0, 1])
    a = rules.parse_descriptors(alts)
    check("both alternate settings are kept, not collapsed",
          [(i["num"], i["alt"]) for i in a["interfaces"]], [("1", "0"), ("1", "1")])
    check("the endpoint lands on the alt that declares it",
          (len(a["interfaces"][0]["eps"]), len(a["interfaces"][1]["eps"])), (0, 1))

    # -- interface association ----------------------------------------------------
    iad = MINIMAL_DEVICE + bytes([
        9, 0x02, 17, 0, 2, 1, 0, 0x80, 50,
        8, 0x0B, 0, 2, 0x0e, 0x03, 0x00, 0])
    check("an interface association is recorded",
          rules.parse_descriptors(iad).get("associations"),
          [{"first": "0", "count": "2", "cls": "14", "sub": "3", "proto": "0"}])

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
