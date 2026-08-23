"""Single-instance lock, a shared allow list, and a read-only viewer channel.

Three files under /run/usbairlock, which is tmpfs, so all of it is per-boot state:

    lock     flock'd for the monitor's lifetime, and holds its pid
    allow    one vid:pid per line, policy that survives the monitor restarting
    sock     newline-delimited JSON, one event per line, for --attach viewers

Two rules the rest of this file exists to keep.

ROOT ONLY. The event stream carries captured HID reports, which is to say the
keystrokes the tool just stopped from reaching the session. A viewer channel that
anyone could open would turn a device-triage tool into a keylogger with a published
socket. The directory is 0700 and the socket 0600, both root-owned, and nothing here
tries to be helpful about relaxing that.

NEVER BREAK THE PROTECTION PATH. Every entry point returns a bool and swallows its own
errors. A read-only filesystem, a stale socket, a viewer that wedges: none of it may
stop the monitor withholding devices, because that is the job and this is a
convenience. When IPC cannot start, the caller reports it and carries on.
"""
import errno, fcntl, json, os, re, socket, time

# Overridable so the lock and socket logic can be tested without root. sudo resets
# the environment by default, so this is not a path an unprivileged caller steers.
RUNDIR = os.environ.get("USBAIRLOCK_RUN", "/run/usbairlock")
LOCK   = os.path.join(RUNDIR, "lock")
ALLOW  = os.path.join(RUNDIR, "allow")
SOCK   = os.path.join(RUNDIR, "sock")

# A viewer that stops reading must not stall the poll loop. Past this much unsent
# backlog the viewer is dropped, on the grounds that protection outranks display.
MAX_BACKLOG = 1 << 20


def _ensure_rundir():
    try:
        os.makedirs(RUNDIR, mode=0o700, exist_ok=True)
        os.chmod(RUNDIR, 0o700)
        return True
    except OSError:
        return False


def holder_pid():
    """The pid of a running monitor, or None. Cheap enough to call before argv parsing."""
    try:
        fd = os.open(LOCK, os.O_RDONLY)
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # held by someone: the lock is the truth, the pid inside is just a label
            try: return int(os.read(fd, 32).decode().strip() or 0) or None
            except (ValueError, OSError): return -1
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None                      # file exists but nobody holds it, stale
    finally:
        os.close(fd)


def read_allow():
    """The shared allow list. Missing file is not an error, it is the common case."""
    try:
        with open(ALLOW) as f:
            return set(ln.strip() for ln in f if ln.strip() and not ln.startswith("#"))
    except OSError:
        return set()


def forget_allow():
    """Drop the shared allow list. Returns what was in it.

    It lives in /run, which is tmpfs, so it survives every monitor restart until the
    machine reboots. That persistence is deliberate -- it is what lets --authorize in
    one terminal reach a monitor in another -- but it means a fresh --paranoid run can
    silently decline to capture a device you trusted hours ago. This is the way back.
    """
    had = read_allow()
    try:
        os.unlink(ALLOW)
    except OSError:
        pass
    return had


def allow_mtime():
    try: return os.stat(ALLOW).st_mtime_ns
    except OSError: return 0


def append_allow(ids):
    """Append ids, then poke the monitor so it re-reads now rather than next tick.

    O_APPEND on a file this small is atomic, so two --authorize runs racing each other
    interleave lines rather than truncating one another. No locking needed for a write
    this shape, and taking the flock here would deadlock against the running monitor.

    Signalling is safe only because of an ordering contract on the other side: the
    monitor installs its SIGUSR1 handler before acquire() publishes the pid. Default
    action for SIGUSR1 is terminate, so getting that order wrong turns this convenience
    into a way to kill the monitor and lift the gate.
    """
    ids = [i for i in ids if i]
    if not ids or not _ensure_rundir():
        return False
    try:
        fd = os.open(ALLOW, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try: os.write(fd, ("".join(i + "\n" for i in ids)).encode())
        finally: os.close(fd)
    except OSError:
        return False
    pid = holder_pid()
    if pid and pid > 0:
        import signal as _sig
        try: os.kill(pid, _sig.SIGUSR1)
        except OSError: pass
    return True


class Holder(object):
    """The running monitor's side: owns the lock, serves viewers, broadcasts events."""

    def __init__(self):
        self.lock_fd = None
        self.srv = None
        self.clients = []            # [[sock, bytearray], ...]
        self.reason = None           # why IPC is unavailable, for the banner

    # -- lifecycle ---------------------------------------------------------------

    def acquire(self):
        """Take the single-instance lock. False means another monitor holds it."""
        if not _ensure_rundir():
            self.reason = "%s is not writable" % RUNDIR
            return True              # degraded, but the monitor still runs
        try:
            self.lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if self.lock_fd is not None:
                os.close(self.lock_fd); self.lock_fd = None
            if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                return False
            self.reason = "lock unavailable: %s" % e
            return True
        os.ftruncate(self.lock_fd, 0)
        os.write(self.lock_fd, ("%d\n" % os.getpid()).encode())
        return True

    def serve(self):
        """Bind the viewer socket. Failure here is not fatal to anything."""
        if self.lock_fd is None:
            return False
        try:
            if os.path.exists(SOCK):
                os.unlink(SOCK)      # we hold the lock, so any socket here is stale
            self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.srv.bind(SOCK)
            os.chmod(SOCK, 0o600)
            self.srv.listen(4)
            self.srv.setblocking(False)
            return True
        except OSError as e:
            self.reason = "viewer socket unavailable: %s" % e
            self.srv = None
            return False

    def close(self):
        for c, _ in self.clients:
            try: c.close()
            except OSError: pass
        self.clients = []
        if self.srv is not None:
            try: self.srv.close()
            except OSError: pass
            try: os.unlink(SOCK)
            except OSError: pass
            self.srv = None
        if self.lock_fd is not None:
            try: os.close(self.lock_fd)     # closing releases the flock
            except OSError: pass
            self.lock_fd = None

    # -- the stream --------------------------------------------------------------

    def broadcast(self, ev, **fields):
        if not self.clients:
            return
        fields["ev"] = ev
        fields.setdefault("t", round(time.time(), 3))
        try:
            line = (json.dumps(fields, default=str) + "\n").encode()
        except (TypeError, ValueError):
            return
        for entry in list(self.clients):
            entry[1] += line
            if len(entry[1]) > MAX_BACKLOG:
                self._drop(entry)
        self.flush()

    def pump(self, hello=None):
        """Accept new viewers and flush pending output. Call once per poll tick."""
        if self.srv is None:
            return
        while True:
            try:
                c, _ = self.srv.accept()
            except (BlockingIOError, OSError):
                break
            c.setblocking(False)
            entry = [c, bytearray()]
            self.clients.append(entry)
            if hello:
                try: entry[1] += (json.dumps(hello, default=str) + "\n").encode()
                except (TypeError, ValueError): pass
        self.flush()

    def flush(self):
        for entry in list(self.clients):
            buf = entry[1]
            while buf:
                try:
                    n = entry[0].send(buf)
                except BlockingIOError:
                    break
                except OSError:
                    self._drop(entry); break
                else:
                    if not n: self._drop(entry); break
                    del buf[:n]

    def _drop(self, entry):
        try: entry[0].close()
        except OSError: pass
        try: self.clients.remove(entry)
        except ValueError: pass

    @property
    def viewers(self):
        return len(self.clients)


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class Journal(object):
    """Append the event stream to a file, as newline-delimited JSON.

    Same events the viewer socket carries, so there is one wire format and a log is
    replayable by whatever reads a viewer. Colour is stripped: escape codes in a
    forensic artifact are noise, and they break every line-oriented tool.

    0600, because this records what a device typed. A world-readable copy of captured
    keystrokes is a worse outcome than not logging at all.

    Flushed per line on purpose. The interesting case is a machine that got yanked or
    a monitor that was killed, and a buffered last line is exactly the one worth having.
    """

    def __init__(self, path):
        self.path, self.fh, self.reason = path, None, None
        try:
            # O_NOFOLLOW: the monitor runs as root and --log takes a path from the
            # command line. A symlink planted at a predictable path -- /tmp/triage.jsonl
            # is exactly the sort of name someone would use twice -- would otherwise
            # have root append through it to a file it should not touch.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                         0o600)
            # fchmod on the descriptor, not chmod on the path. Between the open and a
            # path-based chmod the name can be swapped, and root would then relax the
            # permissions of whatever took its place.
            os.fchmod(fd, 0o600)
            self.fh = os.fdopen(fd, "a", encoding="utf-8")
        except OSError as e:
            self.reason = str(e)

    def write(self, ev, **fields):
        if self.fh is None:
            return
        fields["ev"] = ev
        fields.setdefault("t", round(time.time(), 3))
        if "line" in fields:
            fields["line"] = _ANSI.sub("", str(fields["line"])).rstrip()
        if "lines" in fields:
            fields["lines"] = [_ANSI.sub("", str(l)).rstrip() for l in fields["lines"]]
        try:
            self.fh.write(json.dumps(fields, default=str) + "\n")
            self.fh.flush()
        except (OSError, TypeError, ValueError):
            pass

    def close(self):
        if self.fh is not None:
            try: self.fh.close()
            except OSError: pass
            self.fh = None


def tee(out, holder, journal=None):
    """Wrap a printer so every line it prints also reaches attached viewers.

    The default argument is load-bearing. show_device() calls its out hook with no
    arguments to print a blank separator line, matching p(s="") and Pinned.log(text="").
    A wrapper that required one crashed the monitor on the first arrival, which is the
    worst possible moment: protections were already applied, so the traceback landed
    between withholding a device and being able to look at it.
    """
    def emit(line=""):
        out(line)
        holder.broadcast("log", line=line)
        if journal is not None:
            journal.write("log", line=line)
    return emit


def attach(on_event):
    """Viewer side: stream events from a running monitor until it exits or we do.

    Returns 0 when the monitor closes the stream. KeyboardInterrupt is left to the
    caller, so detaching and the monitor exiting stay distinguishable.
    """
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(SOCK)
    except OSError as e:
        s.close()
        raise e
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                return 0                      # monitor exited, which is a clean end
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try: ev = json.loads(line.decode("utf-8", "replace"))
                except ValueError: continue
                on_event(ev)
    finally:
        try: s.close()
        except OSError: pass
