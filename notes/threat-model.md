# what this catches, and what it cannot

The reference point is **USBValve**: a standalone RP2040 device that sits inline, so the
host never sees the device at all until USBValve has finished with it. That physical
position is what lets it detect things software cannot.

This repo is the **software tier**. It runs on the machine that is actually exposed. Being
honest about the gap is the point, because a tool that implies protection it does not have
is worse than no tool.

## the two tiers

| | software tier (this repo) | hardware tier (planned, `hardware/`) |
| --- | --- | --- |
| position | on the exposed host | inline, between device and host |
| sees | descriptors, claimed classes, driver binds | volts, amps, D+/D- continuity, timing |
| catches | BadUSB, Rubber Ducky, identity switching, opaque devices | all of that, plus the physical layer |
| **cannot** catch | **USB killers, charge-only cables, power anomalies** | needs its own MCU and screen |

## what the software tier genuinely catches

**BadUSB and Rubber Ducky class.** A device that claims an HID keyboard interface, alone
or alongside storage, is the whole attack. It is visible in the descriptors before any
driver binds, and `guard` stops the bind. This is the main threat for an unknown board and
it is fully addressed here.

**Identity switching.** A device advertising multiple configurations can present one
identity, then another. Visible as `bNumConfigurations > 1`.

**Unexpected composition.** A "serial adapter" that also claims HID. A "flash drive" with
a keyboard interface. Class combinations are the tell.

**Opacity.** Vendor-specific class (0xff) means the descriptors tell you nothing and the
device needs a different kind of scrutiny.

## what it CANNOT catch, and why

**USB killers.** These dump a charged capacitor bank, often around -200 V, back down the
data lines. There is no enumeration, no descriptor, no software event. The port is
destroyed in microseconds. **Nothing running on the host can see this coming**, because
the attack is complete before any software runs. Only an inline device with its own
sacrificial front end can. If a board is genuinely suspect, that is the argument for the
hardware tier, and until it exists, for a USB port you are willing to lose.

**Charge-only cables and power-only ports.** Indistinguishable, from the host, from a dead
board or a dead port: no enumeration event either way. The host cannot tell "the data lines
are absent" from "nothing is plugged in". Diagnosing that needs continuity measurement at
the connector, which is a hardware-tier job. (It is also the single most common cause of
"my board will not enumerate", so the software tier should at least say clearly that this
is what it is looking at, rather than going quiet.)

**Power anomalies.** Overcurrent, undervoltage, PD negotiation. The kernel occasionally
logs overcurrent, but by then it has already happened.

## the operating rule

Software tier first, because it is free and it covers the common case. Treat it as
answering "is this device lying about what it is", not "is this device safe to plug in".

For anything genuinely unknown: an isolated box, on an isolated network, with a USB port
you would not mind losing. That is a posture, not a tool.
