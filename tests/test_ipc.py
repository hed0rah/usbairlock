#!/usr/bin/env python3
"""Lock, shared allow list and viewer channel, without needing root or a USB device.

USBAIRLOCK_RUN points the whole thing at a temp directory, so this exercises the real
code paths rather than a mock: a real flock, a real unix socket, a real O_APPEND write.
"""
import os, signal, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="usbairlock-test-")
os.environ["USBAIRLOCK_RUN"] = TMP

from airlock import ipc                                    # noqa: E402  after the env var

G, R, D, N = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def main():
    print(f"\n  {D}run dir: {TMP}{N}\n")

    # The monitor installs this BEFORE taking the lock, because acquire() publishes the
    # pid and SIGUSR1 defaults to terminating the process. Mirror that order here: a
    # test that skipped it would be testing a startup sequence the tool does not use.
    woke = [0]
    signal.signal(signal.SIGUSR1, lambda *_: woke.__setitem__(0, woke[0] + 1))

    # -- the lock ---------------------------------------------------------------
    check("no holder before anything starts", ipc.holder_pid(), None)

    h = ipc.Holder()
    check("first monitor takes the lock", h.acquire(), True)
    check("holder_pid reports our pid", ipc.holder_pid(), os.getpid())

    second = ipc.Holder()
    check("second monitor is refused", second.acquire(), False)
    check("refused holder has no lock fd", second.lock_fd, None)

    check("lock dir is 0700", oct(os.stat(TMP).st_mode & 0o777), "0o700")

    # -- the allow list ---------------------------------------------------------
    check("allow list starts empty", ipc.read_allow(), set())
    stamp = ipc.allow_mtime()

    ipc.append_allow(["303a:1001"])
    check("append lands", ipc.read_allow(), {"303a:1001"})
    check("mtime moves, so a poll tick notices", ipc.allow_mtime() != stamp, True)

    ipc.append_allow(["046d:c52b"])
    check("append accumulates rather than truncating",
          ipc.read_allow(), {"303a:1001", "046d:c52b"})
    check("allow file is 0600", oct(os.stat(ipc.ALLOW).st_mode & 0o777), "0o600")

    ipc.append_allow(["303a:1001"])
    check("a duplicate authorize is harmless",
          ipc.read_allow(), {"303a:1001", "046d:c52b"})
    time.sleep(0.1)
    check("each append signals the holder to re-read now", woke[0], 3)

    # -- the viewer channel -----------------------------------------------------
    check("socket binds", h.serve(), True)
    check("socket is 0600", oct(os.stat(ipc.SOCK).st_mode & 0o777), "0o600")

    got = []
    ready = threading.Event()

    def viewer():
        ready.set()
        try: ipc.attach(got.append)
        except OSError: pass

    t = threading.Thread(target=viewer, daemon=True); t.start()
    ready.wait(2)
    time.sleep(0.2)
    h.pump(hello={"ev": "status", "lines": ["hello"]})
    h.broadcast("log", line="a device arrived")
    time.sleep(0.3)

    check("viewer was accepted", h.viewers, 1)
    check("viewer got the hello status first", got[0]["lines"], ["hello"])
    check("viewer got the broadcast log line", got[1]["line"], "a device arrived")
    check("broadcast events carry a timestamp", "t" in got[1], True)

    # -- the out-hook contract --------------------------------------------------
    # show_device() calls its out hook with NO arguments to print a blank separator
    # line. Every valid hook therefore matches p(s="") and Pinned.log(text=""). A
    # broadcast wrapper that required an argument crashed the monitor on the first
    # arrival, with protections already applied. This is that regression.
    printed = []
    emit = ipc.tee(printed.append, h)
    try:
        emit()
        blank_ok = True
    except TypeError:
        blank_ok = False
    check("tee() accepts a bare call, as show_device makes one", blank_ok, True)
    emit("a line")
    check("tee passes both through to the terminal", printed, ["", "a line"])
    time.sleep(0.2)
    check("tee broadcast the blank line too", got[-2].get("line"), "")
    check("tee broadcast the text line", got[-1].get("line"), "a line")

    # A viewer that dies must not wedge the monitor, and must not linger as a client.
    for c, _ in list(h.clients):
        c.close()
    h.broadcast("log", line="after the viewer died")
    h.flush()
    check("dead viewer is dropped, monitor carries on", h.viewers, 0)

    # -- the journal --------------------------------------------------------------
    # Same wire format as the socket, so a log is replayable by whatever reads a viewer.
    jpath = os.path.join(TMP, "journal.jsonl")
    j = ipc.Journal(jpath)
    check("journal opens", j.reason, None)
    check("journal is 0600, it records what a device typed",
          oct(os.stat(jpath).st_mode & 0o777), "0o600")

    j.write("session", argv="--auto")
    j.write("log", line="\033[32m+ ARRIVED\033[0m  1-1  plain text")
    j.write("status", lines=["\033[2mheld\033[0m", "second"])
    j.close()

    import json as _json
    recs = [_json.loads(l) for l in open(jpath) if l.strip()]
    check("every event landed", [r["ev"] for r in recs], ["session", "log", "status"])
    check("colour is stripped from a logged line",
          recs[1]["line"], "+ ARRIVED  1-1  plain text")
    check("colour is stripped from status lines too",
          recs[2]["lines"], ["held", "second"])
    check("events carry a timestamp", all("t" in r for r in recs), True)

    j2 = ipc.Journal(jpath)
    j2.write("log", line="after reopen")
    j2.close()
    check("reopening appends rather than truncating",
          len([l for l in open(jpath) if l.strip()]), 4)

    dead = ipc.Journal("/proc/nonexistent/usbairlock.jsonl")
    check("an unwritable path reports instead of raising", bool(dead.reason), True)
    dead.write("log", line="swallowed")          # must not raise
    check("and writing to it is a no-op", dead.fh, None)

    tee_out = []
    tee_j = ipc.Journal(os.path.join(TMP, "tee.jsonl"))
    emit2 = ipc.tee(tee_out.append, h, tee_j)
    emit2("through the tee")
    emit2()
    tee_j.close()
    tee_recs = [_json.loads(l) for l in open(os.path.join(TMP, "tee.jsonl")) if l.strip()]
    check("tee writes to the journal as well as the terminal",
          [r.get("line") for r in tee_recs], ["through the tee", ""])

    # -- release ----------------------------------------------------------------
    h.close()
    check("socket is gone after close", os.path.exists(ipc.SOCK), False)
    check("lock is released for the next monitor", ipc.holder_pid(), None)
    check("a new monitor can now start", ipc.Holder().acquire(), True)

    # -- degrading rather than breaking protection ------------------------------
    ipc.RUNDIR = "/proc/nonexistent/usbairlock"
    ipc.ALLOW = ipc.RUNDIR + "/allow"
    check("unwritable run dir does not raise on read", ipc.read_allow(), set())
    check("unwritable run dir reports failure on write", ipc.append_allow(["dead:beef"]), False)

    bad = ipc.Holder()
    check("unwritable run dir still lets the monitor run", bad.acquire(), True)
    check("and it says why", bool(bad.reason), True)

    # -- forget ------------------------------------------------------------------
    # The block above deliberately leaves RUNDIR pointing somewhere unwritable, so put
    # it back before testing anything that expects writes to land.
    ipc.RUNDIR = TMP
    ipc.ALLOW = os.path.join(TMP, "allow")
    ipc.LOCK = os.path.join(TMP, "lock")
    ipc.SOCK = os.path.join(TMP, "sock")

    # The allow list lives in /run (tmpfs), so it outlives every monitor restart until
    # the machine reboots. Found on hardware 2026-08-22: a fresh --paranoid --auto
    # printed "allow list: 1 device(s)" and quietly declined to capture a HIGH keyboard
    # authorized in an earlier session. Persistence is the feature; no way back was not.
    ipc.forget_allow()                 # earlier blocks left entries in this file
    ipc.append_allow(["1a2c:2d23", "090c:1000"])
    check("the list is there before forgetting",
          ipc.read_allow(), {"1a2c:2d23", "090c:1000"})
    check("forget returns what it dropped",
          ipc.forget_allow(), {"1a2c:2d23", "090c:1000"})
    check("and the list is empty afterwards", ipc.read_allow(), set())
    check("forgetting twice is not an error", ipc.forget_allow(), set())
    check("the file is actually gone, not just empty",
          os.path.exists(ipc.ALLOW), False)
    ipc.append_allow(["dead:beef"])
    check("and a later authorize starts a fresh list",
          ipc.read_allow(), {"dead:beef"})
    ipc.forget_allow()

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        import shutil
        shutil.rmtree(TMP, ignore_errors=True)
