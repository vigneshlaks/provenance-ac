"""Layer 4 (OS-level sandboxing) demo -- a complement to, not a
replacement for, application-level provenance tracking (provenance/rules.py).

Verified empirically before building this (ADR-004, see README):
- sandbox-exec is deprecated by Apple (confirmed via its own man page) but
  still functional on this system (macOS 26.5).
- Per-destination network filtering (`(remote ip "host:port")`) is NOT
  available on this macOS version -- sandbox-exec only accepts "*" or
  "localhost" as a host, so this tool can only do blanket allow/deny of
  all network egress, not "allow this destination, block that one." Our
  own app-layer sinks CAN do that (checking which destination, based on
  data provenance) -- genuine destination-selective network filtering
  would need a real firewall (pfctl) or a filtering proxy, neither built
  here.
- Filesystem path scoping DOES work with real granularity (confirmed with
  a subpath deny rule) -- macOS resolves /tmp to /private/tmp (and
  tempfile's default dir similarly), so profile paths must use the
  resolved path or the rule silently no-ops. Confirmed this the hard way:
  a first attempt using an unresolved path did not block the write it was
  supposed to.

Scenario: simulate application-level provenance enforcement being bypassed
or having a gap entirely (exactly the kind of gap already documented in
rules.py/README -- e.g. a value laundered through .upper() before
reaching a sink) -- read a credentials file and write its content outside
the declared workspace, with NO provenance system involved at all. Run
twice: unsandboxed (the write succeeds -- nothing stops it) and sandboxed
(the OS blocks it independently, with zero concept of "provenance" --
it's only enforcing a path boundary).
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

_EXFIL_SCRIPT = """
import sys
credentials_path, outside_path = sys.argv[1], sys.argv[2]
with open(credentials_path) as f:
    content = f.read()
with open(outside_path, "w") as f:
    f.write(content)
print("WROTE:", outside_path)
"""


def _sandbox_profile(outside: pathlib.Path) -> str:
    resolved = outside.resolve()
    return f"""(version 1)
(allow default)
(deny file-write* (subpath "{resolved}"))
(deny network*)
"""


def run_once(sandboxed: bool) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp).resolve()
        workspace = tmp_path / "workspace"
        outside = tmp_path / "outside"
        workspace.mkdir()
        outside.mkdir()

        credentials = workspace / "credentials.txt"
        credentials.write_text("sk-fake-demo-secret")
        exfil_target = outside / "exfiltrated.txt"

        script_path = tmp_path / "exfil.py"
        script_path.write_text(_EXFIL_SCRIPT)

        cmd = [sys.executable, str(script_path), str(credentials), str(exfil_target)]
        if sandboxed:
            profile_path = tmp_path / "profile.sb"
            profile_path.write_text(_sandbox_profile(outside))
            cmd = ["sandbox-exec", "-f", str(profile_path)] + cmd

        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "sandboxed": sandboxed,
            "exfiltration_succeeded": exfil_target.exists(),
            "returncode": result.returncode,
            "stderr": result.stderr.strip()[:200],
        }


def main() -> None:
    print("Layer 4 demo: OS-level sandbox as an independent backstop when")
    print("application-level provenance enforcement is bypassed entirely.\n")

    unsandboxed = run_once(sandboxed=False)
    print(f"Without sandbox: exfiltration_succeeded={unsandboxed['exfiltration_succeeded']}")

    sandboxed = run_once(sandboxed=True)
    print(
        f"With sandbox:    exfiltration_succeeded={sandboxed['exfiltration_succeeded']} "
        f"(stderr: {sandboxed['stderr']!r})"
    )

    print()
    if unsandboxed["exfiltration_succeeded"] and not sandboxed["exfiltration_succeeded"]:
        print(
            "Confirmed: the OS-level sandbox independently stopped the exfiltration "
            "attempt with zero knowledge of 'provenance' as a concept -- it only "
            "enforces a filesystem path boundary, regardless of why a value ended up "
            "outside it."
        )
    else:
        print("WARNING: unexpected result -- see raw output above.")


if __name__ == "__main__":
    main()
