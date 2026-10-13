#!/usr/bin/env python3
"""The monitor's keys, driven through a pty. No devices needed, no root.

Without root nothing is withheld, but every key path still runs: the pick list is
whatever is attached, `a` asks for a `y`, and the confirmed allow reaches do_authorize,
which refuses for want of root. That refusal is the evidence the key went where
--authorize goes. The terminal checks are the ones that matter most: cbreak on while
the monitor runs, ISIG kept so ctrl-c is still a signal, and everything put back on
the way out through the same handler that lifts the protections.
"""
import os, pty, re, select, signal, subprocess, sys, tempfile, termios, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "usbairlock")
G, R, D, N = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


# The pinned block repaints between ESC 7 (save cursor) and ESC 8 (restore), with no
# newlines inside. Drop the whole span, then the remaining escapes, and what is left is
# the scrolling log as a person would read it.
def plain(raw):
    raw = re.sub(rb"\x1b7.*?\x1b8", b"", raw, flags=re.S)
    return re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", raw).decode("utf-8", "replace")


def status_rows(raw):
    """The last painted block, as rows."""
    spans = re.findall(rb"\x1b7(.*?)\x1b8", raw, flags=re.S)
    if not spans:
        return []
    rows = re.split(rb"\x1b\[\d+;1H\x1b\[2K", spans[-1])
    return [re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", r).decode("utf-8", "replace")
            for r in rows if r.strip()]


class Monitor:
    def __init__(self, *args):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ["USBAIRLOCK_RUN"] = tempfile.mkdtemp(prefix="usbairlock-keys-")
            os.environ["COLUMNS"], os.environ["LINES"] = "100", "30"
            os.execv(sys.executable, [sys.executable, BIN, "--interval", "0.2"] + list(args))
        self.raw = b""

    def drain(self, t=0.6):
        out = b""
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                continue
            try: chunk = os.read(self.fd, 65536)
            except OSError: break
            if not chunk: break
            out += chunk
        self.raw += out
        return out

    def press(self, keys, t=0.6):
        os.write(self.fd, keys.encode())
        return self.drain(t)

    def mode(self):
        return termios.tcgetattr(self.fd)[3]

    def stop(self):
        os.write(self.fd, b"\x03")
        tail = self.drain(1.5)
        try: lflag = termios.tcgetattr(self.fd)[3]
        except termios.error: lflag = None
        _, st = os.waitpid(self.pid, 0)
        os.close(self.fd)
        return tail, lflag, os.waitstatus_to_exitcode(st)


def main():
    print()
    # -- the terminal ----------------------------------------------------------
    m = Monitor()
    m.drain(1.5)
    lf = m.mode()
    check("stdin is in cbreak while the monitor runs (ICANON off)", bool(lf & termios.ICANON), False)
    check("keys are not echoed", bool(lf & termios.ECHO), False)
    check("ISIG stays on, so ctrl-c is still a signal", bool(lf & termios.ISIG), True)
    rows = status_rows(m.raw)
    check("the status block has the key row", any("a allow" in r and "? help" in r for r in rows), True)

    # -- the keys ----------------------------------------------------------------
    out = plain(m.press("?"))
    check("? prints the help into the scrolling log", "allow it: admit now" in out, True)

    out = plain(m.press("l"))
    picks = [ln for ln in out.splitlines() if re.match(r"\s*>?\d\s", ln)]
    check("l lists numbered devices", len(picks) >= 1, True)
    check("and marks the picked one", any(ln.lstrip().startswith(">") for ln in picks), True)
    n = len(picks)

    m.press("1")
    rows = status_rows(m.raw)
    check("a digit picks, and the status says which", any("picked" in r for r in rows), True)

    m.press("9" if n < 9 else "1")
    if n < 9:
        rows = status_rows(m.raw)
        check("a digit past the list is refused", any("no device 9" in r for r in rows), True)

    m.press("a")
    rows = status_rows(m.raw)
    check("a asks before allowing", any("y confirms" in r for r in rows), True)
    m.press("n")
    rows = status_rows(m.raw)
    check("any other key cancels", any("allow cancelled" in r for r in rows), True)

    m.press("a")
    m.press("\x1b[A")
    rows = status_rows(m.raw)
    check("an arrow key cancels too, rather than confirming", any("allow cancelled" in r for r in rows), True)

    m.press("a")
    out = plain(m.press("y"))
    check("a then y reaches do_authorize (refused without root, which is the proof)",
          "--authorize needs root" in out, True)

    out = plain(m.press("i", 1.0))
    check("i inspects the picked device through the log", "present" in out and "0x" in out, True)

    # -- the way out -----------------------------------------------------------------
    tail, lflag, rc = m.stop()
    check("ctrl-c still stops the monitor", "restored" in plain(tail.encode() if isinstance(tail, str) else tail), True)
    check("and puts the terminal back (ICANON on)", lflag is not None and bool(lflag & termios.ICANON), True)
    check("and echo back", lflag is not None and bool(lflag & termios.ECHO), True)
    check("exit status is the usual 0", rc, 0)

    # -- --observe -----------------------------------------------------------------
    # Nothing is withheld under --observe, so a keyboard that arrives is live and types
    # into the focused terminal. A single `a` would then be a device admitting itself.
    m = Monitor("--observe")
    m.drain(1.5)
    check("--observe never enters cbreak", bool(m.mode() & termios.ICANON), True)
    rows = status_rows(m.raw)
    check("and the status says why", any("keys off: --observe" in r for r in rows), True)
    out = plain(m.press("?"))
    check("and ? is inert", "allow it: admit now" in out, False)
    m.stop()

    # -- not a terminal ------------------------------------------------------------
    r = subprocess.run([sys.executable, BIN, "--interval", "0.2"], stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=10,
                       env=dict(os.environ, USBAIRLOCK_RUN=tempfile.mkdtemp(prefix="usbairlock-keys-")),
                       preexec_fn=lambda: signal.alarm(2))
    check("piped, the monitor still runs and exits on a signal", r.returncode in (0, -14, 142), True)
    check("and its output has no escape codes", b"\x1b" in r.stdout + r.stderr, False)

    # -- a stale pick must not act on whatever now holds its port ---------------
    # Port addresses are reused. The pick list remembers an address, so without a check
    # `a` then `y` on an old entry would admit the newcomer under the old device's name.
    src = open(BIN).read()
    ns = {}
    exec(compile(src[src.index("def _target("):src.index("def do_describe(")], "<target>", "exec"), ns)
    port = {"1-1": ["1050:0407"]}
    class U:
        resolve = staticmethod(lambda spec: list(port.get(spec, [])))
        id_of = staticmethod(lambda d: d)
    ns["usbinfo"] = U
    t = ns["_target"]
    yubi = {"addr": "1-1", "id": "1050:0407", "name": "YubiKey"}
    check("a pick whose port still holds it acts on the address", t(yubi), "1-1")
    port["1-1"] = ["dead:beef"]
    check("the same port now holding another device refuses", t(yubi), None)
    port.clear()
    check("an unplugged pick refuses", t(yubi), None)
    check("a pick with no address falls back to its vid:pid",
          t({"addr": None, "id": "1050:0407", "name": ""}), "1050:0407")

    print()
    print(f"  {len([x for x in _results if x])}/{len(_results)} passed")
    return 0 if all(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
