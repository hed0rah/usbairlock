#!/usr/bin/env python3
"""No shell metacharacter path from argv to a privileged subprocess.

usbairlock normally runs as root. descriptors() built `lsusb -v -d %s` with shell=True
from a spec that comes straight off the command line, so:

    ./usbairlock --inspect 'zz:zz; any command here; #'

ran that command as root. Confirmed exploitable 2026-08-22 before the fix. A tool whose
entire job is deciding what to trust cannot ship that.

No root and no devices needed: this proves the payload never executes.
"""
import os, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from airlock import usbinfo                                  # noqa: E402

G, R, N = "\033[32m", "\033[31m", "\033[0m"
_results = []


def check(name, got, want):
    ok = got == want
    _results.append(ok)
    print(f"  {G}PASS{N}  {name}" if ok else
          f"  {R}FAIL{N}  {name}\n        got={got!r}\n        want={want!r}")


def main():
    print()
    tmp = tempfile.mkdtemp(prefix="usbairlock-inject-")
    canary = os.path.join(tmp, "pwned")

    # Every shape that works against a shell. If any of these fire, the canary appears.
    payloads = [
        "zz:zz; touch {c}; #",
        "$(touch {c})",
        "`touch {c}`",
        "a | touch {c}",
        "a && touch {c}",
        "a\ntouch {c}",
        "; touch {c}",
        "'; touch {c}; '",
        '"; touch {c}; "',
        "*/../$(touch {c})",
    ]
    try:
        for pat in payloads:
            spec = pat.format(c=canary)
            try:
                usbinfo.descriptors(spec)
            except Exception:
                pass                      # refusing to run at all is a fine outcome
            fired = os.path.exists(canary)
            check(f"payload does not execute: {pat[:22]!r}", fired, False)
            if fired:
                os.unlink(canary)

        # The same argument reaches resolve() and sysfs_for() first. Those glob rather
        # than shell out, but a payload must not blow up either.
        for pat in payloads[:4]:
            spec = pat.format(c=canary)
            try:
                usbinfo.resolve(spec)
                usbinfo.sysfs_for(spec)
            except Exception as e:
                check(f"resolve() survives {pat[:16]!r}", f"raised {e}", "no raise")
        check("resolve/sysfs_for handle hostile specs without raising", True, True)
        check("and still no canary after those", os.path.exists(canary), False)

        # A malformed vid:pid must be refused rather than handed to lsusb hopefully.
        check("a spec that is not a vid:pid is refused outright",
              usbinfo.descriptors("not-a-device"), {})
        check("and neither is a partial one", usbinfo.descriptors("0bda:"), {})
        check("a well formed vid:pid is still accepted",
              isinstance(usbinfo.descriptors("dead:beef"), dict), True)

        # The whole binary, end to end, as root would run it.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        r = subprocess.run([sys.executable, os.path.join(root, "usbairlock"),
                            "--inspect", f"zz:zz; touch {canary}; #"],
                           capture_output=True, text=True, cwd=root, timeout=30)
        check("--inspect with a payload does not execute it", os.path.exists(canary), False)
        check("and it exits rather than hanging", r.returncode in (0, 1, 2), True)

        # sh() still exists for fixed strings. Guard against it regaining a caller that
        # interpolates: every sh( call site in the package must be a literal.
        import re
        bad = []
        for fn in ("usbinfo.py", "capture.py", "protect.py", "rules.py", "ipc.py", "live.py"):
            path = os.path.join(root, "airlock", fn)
            if not os.path.exists(path):
                continue
            for i, line in enumerate(open(path), 1):
                m = re.search(r"[^_\w]sh\(([^)]*)", line)
                if m and ("%" in m.group(1) or "f\"" in m.group(1) or "+" in m.group(1)
                          or "format(" in m.group(1)):
                    bad.append(f"{fn}:{i}")
        check("no sh() call interpolates a value", bad, [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # -- config search under sudo ------------------------------------------------
    # The monitor needs root. sudo sets HOME=/root, and the banner tells you to write
    # ~/.config/usbairlock/config -- which unprivileged lands in YOUR home and was then
    # never read by the run that matters. The documented workflow did nothing.
    from airlock import config as cfgmod
    saved = dict(os.environ)
    try:
        os.environ["HOME"] = "/root"
        os.environ.pop("SUDO_USER", None)
        plain = cfgmod.search_paths()
        check("without sudo, only root's config and /etc",
              any("/root/" in p_ for p_ in plain) and len(plain) == 2, True)

        os.environ["SUDO_USER"] = "nobody"
        under = cfgmod.search_paths()
        check("under sudo, the invoking user's config is searched too",
              len(under) > len(plain), True)
        check("root's own config still takes precedence", "/root/" in under[0], True)
        check("/etc stays last", under[-1], "/etc/usbairlock.conf")

        os.environ["SUDO_USER"] = "no-such-user-exists-here"
        check("an unknown SUDO_USER is skipped rather than raising",
              isinstance(cfgmod.search_paths(), list), True)
    finally:
        os.environ.clear()
        os.environ.update(saved)

    # the parser must never evaluate a config value
    import inspect as _i2
    src2 = _i2.getsource(cfgmod)
    check("config parsing does not eval or exec",
          ("eval(" in src2) or ("exec(" in src2), False)

    # -- the helper tools ---------------------------------------------------------
    # tools/dump and tools/identify are what the README tells you to run AFTER deciding
    # you do not trust a device. Both used shell=True. dump's was the worst in the repo:
    # `chip` is parsed out of the DEVICE'S OWN response to flash-id and interpolated
    # into the read-flash command, so a device answering with a crafted chip name got
    # its text into a shell command run against the machine it was plugged into.
    import ast as _ast
    root2 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def shell_true_calls(path, only_dynamic=False):
        """Calls with shell=True. Parsed, not grepped -- the fix's own comments mention
        shell=True and a grep would match the explanation rather than the code.

        only_dynamic drops the ones whose command is a plain string literal. A constant
        like subprocess.run("dmesg", shell=True) carries nothing from outside and is
        fine; an f-string or a concatenation is the bug.
        """
        tree = _ast.parse(open(path).read())
        hits = []
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            if not any(kw.arg == "shell" and getattr(kw.value, "value", None) is True
                       for kw in (node.keywords or [])):
                continue
            first = node.args[0] if node.args else None
            literal = isinstance(first, _ast.Constant) and isinstance(first.value, str)
            if only_dynamic and literal:
                continue
            hits.append(getattr(node, "lineno", "?"))
        return hits

    for tool in ("dump", "identify"):
        path = os.path.join(root2, "tools", tool)
        check(f"tools/{tool} makes no shell=True call", shell_true_calls(path), [])
        src = open(path).read()
        check(f"tools/{tool} validates a port shape rather than a bare prefix",
              "_PORT_RE" in src, True)

    # usbairlock still shells out for `dmesg`, a constant that carries nothing from
    # outside. Exactly one place is allowed to pass a variable to shell=True: the sh()
    # wrapper in usbinfo, whose entire contract is that callers hand it a fixed string.
    # Everything else must be argv. So assert the inventory rather than a blanket zero,
    # and pair it with the call-site check below -- neither is sufficient alone.
    dynamic = {}
    for mod_path in ("usbairlock", "airlock/usbinfo.py", "airlock/capture.py",
                     "airlock/protect.py", "airlock/ipc.py", "airlock/rules.py",
                     "airlock/config.py", "airlock/live.py"):
        full = os.path.join(root2, mod_path)
        if os.path.exists(full):
            hits = shell_true_calls(full, only_dynamic=True)
            if hits:
                dynamic[mod_path] = hits
    check("only the documented sh() wrapper passes a variable to a shell",
          sorted(dynamic), ["airlock/usbinfo.py"])
    check("and there is exactly one of it",
          len(dynamic.get("airlock/usbinfo.py", [])), 1)

    # a device-supplied name is a filename component, not a command fragment
    import importlib.util as _u
    import importlib.machinery as _m
    dump_path = os.path.join(root2, "tools", "dump")
    # tools/dump has no .py suffix, so importlib cannot infer a loader for it
    spec = _u.spec_from_file_location(
        "dumptool", dump_path, loader=_m.SourceFileLoader("dumptool", dump_path))
    mod = _u.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass

    for raw in ("ESP32; touch /tmp/x; #", "$(id)", "`id`", "a|b", "../../etc/passwd",
                "", "   ", "x" * 200):
        got = mod.safe_name(raw)
        bad = set(got) & set(";|&$`()<>\\ '\"*?/\n")
        check(f"safe_name strips shell characters from {raw[:16]!r}", bad, set())
        check(f"safe_name never returns empty for {raw[:16]!r}", bool(got), True)
    check("a plain chip name survives readable", mod.safe_name("ESP32-C3"), "ESP32-C3")
    check("and a long one is bounded", len(mod.safe_name("x" * 500)) <= 40, True)

    ok = sum(_results)
    print(f"\n  {ok} passed, {len(_results) - ok} failed\n")
    return 0 if ok == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
