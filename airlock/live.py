"""A pinned status region above scrolling output. The apt / docker-pull pattern.

Normal output scrolls in the upper region as usual, so scrollback still works and you can
copy text out of it. The bottom few lines are pinned: they stay put and redraw in place.

Implemented with the DECSTBM scroll region, which is what apt and docker use:

    ESC[1;{h}r      restrict scrolling to rows 1..h
    ESC[{h+1};1H    park the cursor below the region and draw the pinned block there
    ESC[r           release the region

Chosen over a full-screen alternate-buffer TUI on purpose. A TUI takes over the terminal,
loses your scrollback, and cannot be piped or copied out of. This keeps a normal terminal
session and just refuses to let the status scroll away.

Anything that changes terminal state MUST register a restore on the same path the signal
handler uses, or Ctrl-C leaves the user with a wedged terminal. See protect.add_cleanup.
"""
import os, select, shutil, signal, sys, time

class Pinned:
    def __init__(self, height=6, enabled=True):
        self.height = height
        self.lines = []
        self.enabled = enabled and sys.stdout.isatty()
        self._active = False
        self._rows = 0

    # -- lifecycle ------------------------------------------------------------
    def __enter__(self):
        if not self.enabled: return self
        try:
            from . import protect
            protect.add_cleanup(self.close)
        except Exception:
            pass
        self._size()
        sys.stdout.write("\n" * self.height)          # make room, keep prior output
        sys.stdout.write(f"\033[1;{self._rows - self.height}r")
        sys.stdout.write(f"\033[{self._rows - self.height};1H")
        sys.stdout.flush()
        self._active = True
        return self

    def __exit__(self, *a): self.close()

    def close(self):
        if not self._active: return
        self._active = False
        sys.stdout.write("\033[r")                     # release the scroll region
        sys.stdout.write(f"\033[{self._rows};1H\033[?25h\n")
        sys.stdout.flush()

    def _size(self):
        try: cols, rows = shutil.get_terminal_size()
        except Exception: cols, rows = 80, 24
        self._cols, self._rows = cols, max(rows, self.height + 4)

    # -- use ------------------------------------------------------------------
    def _sync(self):
        """Re-establish the scroll region if the terminal changed size.

        A font change or a window resize alters the row count, and the old DECSTBM
        region no longer matches the screen. The cursor is then parked below the new
        region, inside the pinned block, so everything log() writes lands in the pinned
        area and paint() overwrites it on the same tick. Output looks like it stopped
        dead while the status block carries on updating, which reads as a hung tool.

        No SIGWINCH handler on purpose: the monitor repaints the status every poll tick,
        so checking the size here corrects it within one interval without doing terminal
        writes from inside a signal handler.
        """
        prev = self._rows
        self._size()
        if self._rows != prev and self._active:
            sys.stdout.write(f"\033[1;{self._rows - self.height}r")
            sys.stdout.write(f"\033[{self._rows - self.height};1H")
            sys.stdout.flush()

    def log(self, text=""):
        """Print into the scrolling region, then repaint the pinned block."""
        self._sync()
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        self.paint()

    def set(self, lines):
        self._sync()
        self.lines = lines
        self.paint()

    def paint(self):
        if not self._active:
            return
        self._size()
        top = self._rows - self.height + 1
        out = ["\0337"]                                # save cursor
        out.append(f"\033[1;{self._rows - self.height}r")
        for i in range(self.height):
            out.append(f"\033[{top + i};1H\033[2K")     # park, clear the line
            if i < len(self.lines):
                out.append(self.lines[i][: self._cols + 64])
        out.append("\0338")                            # restore cursor
        sys.stdout.write("".join(out))
        sys.stdout.flush()


class Keys:
    """Single keystrokes from the terminal, read between poll ticks.

    Replaces the monitor's sleep with a select on stdin, so a key arrives at once and an
    idle tick still waits the full interval. No thread, no line editor: one character
    per action, which is the shape the pinned block already has room to explain.

    cbreak, not raw. ICANON and ECHO go off so a key is delivered as it is pressed and
    not shown; ISIG stays on so ctrl-c is still a signal and still reaches the handler
    that lifts the protections. Restoring the terminal is registered on that handler's
    path (protect.add_cleanup) for the same reason Pinned does it: os._exit skips
    context managers, and a stuck cbreak terminal is exactly the sort of wedge this
    tool is meant never to leave behind.

    Off unless BOTH ends are a terminal and this process owns the foreground. Reading a
    tty from a background job raises SIGTTIN, which stops the process, and a stopped
    monitor is one that holds devices and answers nothing. SIGTTIN is ignored while keys
    are on so a later ctrl-z / bg cannot do the same: the read then fails with EIO,
    which reads as no key.
    """
    def __init__(self, off=None):
        """`off` is a reason to leave keys disabled, shown to the operator in the status."""
        self.fd = None
        self._saved = None
        self._prev_ttin = None
        self.reason = None
        self.enabled = False
        if off:
            self.reason = off
        elif not (sys.stdin.isatty() and sys.stdout.isatty()):
            self.reason = "not a terminal"
        else:
            self.enabled = True

    def __enter__(self):
        if not self.enabled:
            return self
        import termios
        try:
            self.fd = sys.stdin.fileno()
            if os.tcgetpgrp(self.fd) != os.getpgrp():
                self.enabled, self.reason = False, "not in the foreground"
                return self
            self._saved = termios.tcgetattr(self.fd)
            mode = list(self._saved)
            mode[3] &= ~(termios.ICANON | termios.ECHO)
            mode[6] = list(mode[6])
            mode[6][termios.VMIN], mode[6][termios.VTIME] = 1, 0
            termios.tcsetattr(self.fd, termios.TCSANOW, mode)
        except (termios.error, OSError, ValueError) as e:
            self.enabled, self.reason, self._saved = False, str(e), None
            return self
        try:
            self._prev_ttin = signal.signal(signal.SIGTTIN, signal.SIG_IGN)
        except (OSError, ValueError):
            pass
        try:
            from . import protect
            protect.add_cleanup(self.close)
        except Exception:
            pass
        return self

    def __exit__(self, *a): self.close()

    def close(self):
        if self._saved is None:
            return
        import termios
        saved, self._saved = self._saved, None
        try: termios.tcsetattr(self.fd, termios.TCSANOW, saved)
        except (termios.error, OSError): pass
        if self._prev_ttin is not None:
            try: signal.signal(signal.SIGTTIN, self._prev_ttin)
            except (OSError, ValueError): pass

    def wait(self, timeout):
        """Sleep up to `timeout`, returning early with whatever was typed, else ''."""
        if not self.enabled:
            time.sleep(timeout)
            return ""
        try:
            r, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            return ""
        if not r:
            return ""
        try:
            return os.read(self.fd, 64).decode("utf-8", "replace")
        except OSError:
            return ""
