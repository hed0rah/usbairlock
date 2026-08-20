#!/usr/bin/env python3
"""Threat detection tests, run with plain python3. No pytest, no dependencies.

    python3 tests/test_threats.py

These exist because the detector had never fired on real hardware. Every device
available for testing was internal and genuinely benign, so "no suspect claims" was
an unfalsified claim. Synthetic descriptors let the dangerous paths be exercised
without owning a Rubber Ducky.

Interface fields mirror lsusb -v output, which prints class/subclass/protocol as
DECIMAL strings. Getting that wrong silently disables every rule, so the fixtures
use the same representation the parser actually receives.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import usbinfo

def dev(interfaces, **kw):
    d = {"interfaces": [], "n_configs": kw.pop("n_configs", "1")}
    d.update(kw)
    for i, (cls, sub, proto) in enumerate(interfaces):
        d["interfaces"].append({"num": str(i), "cls": str(cls), "sub": str(sub),
                                "proto": str(proto), "eps": []})
    return d

def levels(d):
    return {lvl for lvl, _, _ in usbinfo.threats(d)}

CASES = []
def case(name, device, expect_worst, why):
    CASES.append((name, device, expect_worst, why))

# class numbers as lsusb prints them (decimal): 3=HID, 8=storage, 2=CDC, 10=CDC-data,
# 224=wireless, 255=vendor, 14=video, 9=hub
case("BadUSB: storage that also types",
     dev([(8,6,80),(3,1,1)]), "HIGH",
     "mass storage plus a boot keyboard is the canonical malicious-USB shape")
case("Rubber Ducky: keyboard only",
     dev([(3,1,1)]), "HIGH",
     "a bare boot-protocol keyboard can inject keystrokes the moment it binds")
case("innocent flash drive",
     dev([(8,6,80)]), None,
     "mass storage alone is ordinary and must not be flagged")
case("Bluetooth radio",
     dev([(224,1,1),(224,1,1)]), None,
     "class 224 covers Bluetooth AND RNDIS; flagging every Bluetooth trains you to ignore the tool")
case("RNDIS network adapter",
     dev([(224,1,3)]), "MED",
     "RNDIS can take over DNS and routing on bind")
case("CDC ethernet",
     dev([(2,6,0),(10,0,0)]), "MED",
     "CDC-ECM is the same takeover risk wearing a different class")
case("ESP32 native USB serial",
     dev([(2,2,0),(10,0,0)]), None,
     "a plain CDC serial device is what most dev boards look like")
case("serial adapter that also claims HID",
     dev([(2,2,0),(10,0,0),(3,0,0)]), "MED",
     "legitimate for some debug probes, suspicious on a plain USB-serial adapter")
case("identity switcher",
     dev([(2,2,0)], n_configs="3"), "MED",
     "multiple configurations let a device present one identity then another")
case("opaque vendor device",
     dev([(255,0,0)]), "LOW",
     "vendor-specific class tells you nothing; judge it by behaviour")
case("mouse",
     dev([(3,1,2)]), "MED",
     "pointer injection, and a common cover for a second HID interface")
case("webcam",
     dev([(14,1,0),(14,2,0)]), None,
     "video class is ordinary")
case("over-budget power draw",
     dev([(8,6,80)], max_power="900mA"), "LOW",
     "above the 500mA USB2 budget")
case("no descriptors readable",
     dev([]), "LOW",
     "an unauthorized or half-enumerated device should say so, not read as clean")

def worst(d):
    l = levels(d)
    for lvl in ("HIGH", "MED", "LOW"):
        if lvl in l: return lvl
    return None

def main():
    width = max(len(n) for n, *_ in CASES)
    passed = failed = 0
    for name, device, expect, why in CASES:
        got = worst(device)
        ok = got == expect
        mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {mark}  {name:{width}s}  expected={str(expect):5s} got={str(got):5s}")
        if not ok:
            print(f"        {why}")
            print(f"        threats returned: {usbinfo.threats(device)}")
            failed += 1
        else:
            passed += 1
    print(f"\n  {passed} passed, {failed} failed")
    return 1 if failed else 0

sys.exit(main())
