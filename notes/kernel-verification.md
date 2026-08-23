# Verification against the kernel source

Every load-bearing claim in the README and in the code comments, checked line by line
against `linux-source-6.8.0` (`drivers/usb/core/`, `drivers/base/`). Done 2026-08-23.

The running kernel here is 7.0.0-28 and the readable source is 6.8.0. These interfaces
have been stable since 4.13, and the two behavioural claims that can be tested live were
tested on 7.0.0-28 and agree with the 6.8 source (see the last two rows). Anything a
future kernel changes should be re-checked here rather than assumed.

| # | claim | verdict | source |
|---|---|---|---|
| 1 | authorization is decided once, in the constructor | confirmed | `usb.c:747`, the line immediately before `return dev` in `usb_alloc_dev()` |
| 2 | it reads `hcd->dev_policy`, which `authorized_default` writes | confirmed | `usb.c:612`, `sysfs.c:931` |
| 3 | three policies: NONE / ALL / INTERNAL, and INTERNAL means firmware-hard-wired ports | confirmed | `usb.c:605-625`; INTERNAL tests `connect_type == USB_PORT_CONNECT_TYPE_HARD_WIRED` |
| 4 | a value above 2 clamps to ALL rather than erroring | confirmed | `sysfs.c:931` -- `val <= USB_DEVICE_AUTHORIZE_INTERNAL ? val : USB_DEVICE_AUTHORIZE_ALL` |
| 5 | enumeration reads descriptors with no authorization check in it | confirmed | `hub.c:2488` `usb_enumerate_device()`, 43 lines, zero occurrences of `authoriz`; called from `usb_new_device()` under the kernel's own comment `/* Read descriptors */` |
| 6 | product, manufacturer and serial are cached during that read | confirmed | three `usb_cache_string()` calls in the same function |
| 7 | authorization gates configuration, not enumeration | confirmed | `message.c:2059` -- `if (dev->authorized == 0 \|\| configuration == -1) configuration = 0;` |
| 8 | interfaces inherit their own gate, copied once, the same way | confirmed | `message.c:2166` -- `intf->authorized = !!HCD_INTF_AUTHORIZED(hcd)` inside `usb_set_configuration()` |
| 9 | a claim reports EBUSY before it reports the authorization state | confirmed | `driver.c` `usb_driver_claim_interface()`: `if (dev->driver) return -EBUSY;` precedes `if (!iface->authorized) return -ENODEV;` |
| 10 | ENOENT is what an unauthorized DEVICE produces, not ENODEV | confirmed | `devio.c` `claimintf()` -> `usb_ifnum_to_if()` returns NULL when `!config` (`usb.c:354`), and an unauthorized device was forced to config 0 by row 7 |
| 11 | suspending `drivers_autoprobe` stops a driver binding to an interface that appears while it is off | confirmed | `bus.c:572` -- `if (sp->drivers_autoprobe) device_initial_probe(dev);` in `bus_probe_device()`. Also `bus.c:715`, which is why a driver *registering* while it is off attaches to nothing either |
| 12 | `drivers_probe` re-runs matching for one named device | confirmed | `bus.c:309` `drivers_probe_store()` -> `bus_rescan_devices_helper()` |

## the full usbfs claim path

`USBDEVFS_CLAIMINTERFACE` reaches `claimintf()` in `devio.c`, which returns, in order:

    ifnum >= 8*sizeof(ps->ifclaimed)   -> EINVAL   claim set is a bitmask in a long
    already claimed                    -> 0        idempotent
    ps->privileges_dropped             -> EACCES
    usb_ifnum_to_if() == NULL          -> ENOENT   unconfigured device: config is NULL
    usb_driver_claim_interface()       -> EBUSY    a driver holds it
                                       -> ENODEV   the interface gate is shut

All six are named in `capture.py`. EINVAL is unreachable for a normal device and
perfectly reachable for a hostile descriptor, which is the case this tool exists for.

## tested live, on the running 7.0.0-28

- writing `2` to `authorized_default` sticks; writing `3` reads back as `1`. Matches row 4.
- a device that enumerated under a shut gate stays `authorized=0` after the gate is
  restored, and its interfaces never appear. Matches row 1, and is the reason
  `restore_all()` re-authorizes what it withheld instead of only putting the gate back.

## a second pass, on what the tool DOES rather than what it claims

| # | finding | source |
|---|---|---|
| 13 | authorising a device does not merely flip a flag: `usb_authorize_device()` calls `usb_choose_configuration()` and `usb_set_configuration()` expressly to register interfaces and let drivers bind | `hub.c` |
| 14 | ...but those interfaces are born with `intf->authorized` copied from the still-shut gate, so the bind the kernel attempts is rejected in `usb_probe_interface()` and leaves `Interface N is not authorized for usage` in the log. Authorising them afterwards retries nothing, which is why `drivers_probe` is needed | `message.c`, `driver.c:340` |
| 15 | deauthorising a LIVE device calls `usb_set_configuration(dev, -1)`, and -1 forces configuration 0 by the same line as row 7. Its interfaces are torn down immediately. This is the source-level reason a hub deauthorised mid-session strands everything behind it: the hub driver loses its interface and unbinds | `hub.c`, `message.c:2059` |
| 16 | `connect_type` has exactly three values, UNKNOWN / HOT_PLUG / HARD_WIRED, which is what policy 2 in row 3 discriminates on | `include/linux/usb.h:504` |
| 17 | **`usbfs_snoop` does not log all USB traffic.** It is referenced in one file, `devio.c`, and every call site is on the usbfs path -- userspace access through `/dev/bus/usb`. Device-to-kernel-driver traffic never reaches it, so a bound keyboard logs nothing. Payloads truncate at `usbfs_snoop_max`, 65536 by default | `devio.c:112-118`, grep across `drivers/usb/core/` |

Row 17 was a real overstatement in this tool and is corrected. Enabling snoop, watching a
bound device, seeing an empty log and concluding the device is quiet would be exactly the
blind-tool-reports-all-clear failure this program is not allowed to have. For
device-to-driver traffic the answer is usbmon.
