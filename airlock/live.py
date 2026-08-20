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
import os, shutil, sys

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
