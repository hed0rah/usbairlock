#!/usr/bin/env python3
"""USB tree shape, derived from the sysfs name alone. No devices, no root.

sysfs encodes the whole topology in the device name, so parentage needs no lookups:
`1-2.3` is port 3 of the hub that is itself on port 2 of root hub `usb1`. These exist
because an unauthorized hub silently strands everything beneath it, and until the
listing said so the operator saw a device they had allowed and total silence behind it.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import usbinfo                                 # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def main():
    print()
    # -- parentage ---------------------------------------------------------------
    for addr, parent in [("usb1", None), ("usb4", None),
                         ("1-1", "usb1"), ("1-14", "usb1"), ("2-1", "usb2"),
                         ("1-2.3", "1-2"), ("1-2.3.4", "1-2.3"), ("2-1.4", "2-1")]:
        check(f"parent_of({addr})", usbinfo.parent_of(addr), parent)
    check("parent_of(None) is None", usbinfo.parent_of(None), None)
    check("parent_of('') is None", usbinfo.parent_of(""), None)

    # -- depth -------------------------------------------------------------------
    for addr, d in [("usb1", 0), ("1-1", 1), ("1-2.3", 2), ("1-2.3.4", 3)]:
        check(f"depth_of({addr})", usbinfo.depth_of(addr), d)

    # -- stranding ---------------------------------------------------------------
    # usb1 open, the hub on 1-2 shut. everything under 1-2 is enumerated and dead.
    auth = {"usb1": "1", "1-1": "1", "1-2": "0", "1-2.3": "1", "1-2.3.4": "1"}
    check("a directly attached device is not stranded",
          usbinfo.stranded_by("1-1", auth), None)
    check("the shut hub is not itself stranded",
          usbinfo.stranded_by("1-2", auth), None)
    check("a device on the shut hub names it",
          usbinfo.stranded_by("1-2.3", auth), "1-2")
    check("and so does one two levels below it",
          usbinfo.stranded_by("1-2.3.4", auth), "1-2")
    check("a root hub is never stranded",
          usbinfo.stranded_by("usb1", auth), None)
    check("nothing is stranded when every hub is open",
          usbinfo.stranded_by("1-2.3", {"usb1": "1", "1-2": "1"}), None)

    # An unknown ancestor is not evidence of anything. Reporting a device as stranded
    # because its parent is merely absent from the map would invent a fault.
    check("an ancestor we know nothing about does not strand a device",
          usbinfo.stranded_by("1-2.3", {"usb1": "1"}), None)

    # Malformed names must terminate rather than walk forever.
    check("a self-referential name terminates",
          usbinfo.stranded_by("1-2.3", {"1-2": "1", "usb1": "1"}), None)

    # -- what a withheld hub actually does ---------------------------------------
    # Proven on hardware 2026-08-22: plugging a dock holding a MIDI controller and a
    # flash drive into a closed gate listed the hub alone. The two devices did not
    # appear as unreachable, they did not appear AT ALL -- a withheld hub binds no
    # driver, so nothing behind it enumerates and no child exists in sysfs to mark.
    # So the warning has to live on the hub, which does exist.
    auth2 = {"usb1": "1", "1-4": "0", "1-1": "1"}
    check("a withheld hub is flagged as opaque",
          usbinfo.blinds_downstream("1-4", auth2, True), True)
    check("an authorized hub is not",
          usbinfo.blinds_downstream("1-1", {"1-1": "1"}, True), False)
    check("a withheld NON-hub is not opaque, it is just withheld",
          usbinfo.blinds_downstream("1-1", {"1-1": "0"}, False), False)
    check("a root hub is never reported opaque",
          usbinfo.blinds_downstream("usb1", {"usb1": "0"}, True), False)
    check("an address we know nothing about is not opaque",
          usbinfo.blinds_downstream("1-9", auth2, True), False)

    # -- the interface gate makes a hub opaque too, and that is the DEFAULT -----------
    # Found on hardware 2026-08-23. withhold_interface leaves the device authorized and
    # shuts the interface, so a hub held by the default configuration was every bit as
    # opaque and the warning never fired. The test is the driver, not the device gate.
    check("a hub with no driver is opaque even though the DEVICE is authorized",
          usbinfo.blinds_downstream("1-4", {"1-4": "1"}, True, "none"), True)
    check("and the same for an empty driver field",
          usbinfo.blinds_downstream("1-4", {"1-4": "1"}, True, ""), True)
    check("and for the dash the listing uses when there is nothing",
          usbinfo.blinds_downstream("1-4", {"1-4": "1"}, True, "-"), True)
    check("a hub WITH the hub driver bound is not opaque",
          usbinfo.blinds_downstream("1-4", {"1-4": "1"}, True, "hub"), False)
    check("the device gate still counts on its own, driver or not",
          usbinfo.blinds_downstream("1-4", {"1-4": "0"}, True, "hub"), True)
    check("a root hub is still never opaque, even driverless",
          usbinfo.blinds_downstream("usb1", {"usb1": "1"}, True, "none"), False)
    check("a driverless NON-hub is not opaque, it is just unbound",
          usbinfo.blinds_downstream("1-4", {"1-4": "1"}, False, "none"), False)
    # A caller with no driver information must not have one invented for it.
    check("driver omitted falls back to the device gate alone",
          usbinfo.blinds_downstream("1-4", {"1-4": "1"}, True), False)

    # stranded_by is kept for a tree someone ELSE deauthorized, where the children did
    # enumerate first. It is simply not reachable through this tool's own gate.
    check("stranded_by still describes a hand-deauthorized tree",
          usbinfo.stranded_by("1-2.3", {"usb1": "1", "1-2": "0"}), "1-2")

    # -- port order --------------------------------------------------------------
    # A ten-port hub sorted as strings lists port 10 above port 2, which matches
    # nothing printed on the plastic. This box has no hub to demonstrate that on, so
    # the unit test is the only place the crossing-into-double-digits case is checked.
    devs = ["1-14", "1-1", "usb1", "1-5", "1-2.10", "1-2.2", "1-2", "usb2", "2-1"]
    check("siblings sort by port number, not by string",
          sorted(devs, key=usbinfo.sort_key),
          ["usb1", "1-1", "1-2", "1-2.2", "1-2.10", "1-5", "1-14", "usb2", "2-1"])
    check("a root hub sorts above its own devices",
          sorted(["1-1", "usb1"], key=usbinfo.sort_key), ["usb1", "1-1"])
    check("buses stay grouped and in order",
          sorted(["2-1", "10-1", "1-1"], key=usbinfo.sort_key), ["1-1", "2-1", "10-1"])
    check("a malformed address sorts without raising",
          isinstance(usbinfo.sort_key("1-x.y"), tuple), True)
    check("an empty address sorts without raising", usbinfo.sort_key(""), ())

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
