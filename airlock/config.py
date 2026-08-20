"""Configuration: built-in defaults, overridden by a file, overridden by flags.

Deliberately a plain key=value file with [sections]. No yaml, no toml parser, no
dependency: this runs on a triage box that may be a fresh Pi with nothing installed.
"""
import os

DEFAULTS = {
    "protections": {
        # Per-INTERFACE authorization (kernel 4.13+) is the default because it is the
        # better posture on both counts. The device authorizes and configures normally,
        # so its descriptors are fully readable and it does not sit unconfigured, but no
        # interface binds a driver.
        #
        # withhold_device, the device-level gate, is off by default because it is blunter:
        # it hides the device's own interfaces, so nothing can inspect or capture them.
        #
        # A correction worth keeping: withhold_interface was chosen partly on a guess that it
        # would avoid the re-enumeration loop cheap HID firmware falls into when it is not
        # driven. It does NOT. Observed on a plain USB keyboard with the device authorized
        # and only its interfaces held: it still reset itself every few seconds. The loop
        # comes from nothing claiming the interface, not from the device being
        # unauthorized. capture_forever exists to survive it.
        "withhold_interface": True,
        "withhold_device": False,
        # refuse the usbhid driver entirely. Stops a BadUSB keyboard dead even if
        # something authorizes it. Costs you USB keyboards and mice while active, so it
        # is off by default: on a desktop with a USB keyboard it locks you out.
        "unbind_hid": False,
        # refuse usb-storage. Stops mass-storage autoprobing.
        "unbind_storage": False,
        # refuse USB ethernet/RNDIS. A device claiming to be a network adapter can
        # take over DNS and routing on connect.
        "unbind_net": False,
        # raw USB traffic into the kernel ring buffer. Off even under --paranoid: it is
        # extremely loud and will bury anything else in dmesg.
        "usbfs_snoop": False,
    },
    "monitor": {
        "poll_interval": 1.0,
        "auto_inspect": True,
        "descriptors": "summary",     # none | summary | full
        "bell_on_high": True,          # terminal bell when a HIGH threat appears
    },
    "paths": {
        "dumps": "dumps",
    },
}

SEARCH = [
    os.path.expanduser("~/.config/usbairlock/config"),
    "/etc/usbairlock.conf",
]

def _coerce(v):
    s = str(v).strip()
    low = s.lower()
    if low in ("true", "yes", "on", "1"):  return True
    if low in ("false", "no", "off", "0"): return False
    try:
        return float(s) if "." in s else int(s)
    except ValueError:
        return s

def load(explicit=None):
    """defaults <- first config file found (or the explicit one) <- caller's flags"""
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    used = None
    candidates = [explicit] if explicit else SEARCH
    for path in candidates:
        if path and os.path.isfile(path):
            used = path
            section = None
            for raw in open(path):
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip()
                    cfg.setdefault(section, {})
                elif "=" in line and section:
                    k, v = line.split("=", 1)
                    cfg[section][k.strip()] = _coerce(v)
            break
    return cfg, used

def sample():
    out = ["# usbairlock configuration",
           "# every value here is also settable as a command-line flag,",
           "# and the flag wins.", ""]
    for sec, vals in DEFAULTS.items():
        out.append(f"[{sec}]")
        for k, v in vals.items():
            out.append(f"{k} = {str(v).lower() if isinstance(v,bool) else v}")
        out.append("")
    return "\n".join(out)
