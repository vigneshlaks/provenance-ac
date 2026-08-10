"""Layer 4, an OS level sandboxing demo. This is a complement to
application level provenance tracking in provenance/rules.py, not a
replacement for it.

Some notes on sandbox-exec, which this demo depends on. It is deprecated
by Apple but still functional on this system, macOS 26.5. Filtering
network access by destination, using a rule like (remote ip "host:port"),
isn't available on this macOS version. sandbox-exec only accepts "*" or
"localhost" as a host, so it can only do a blanket allow or deny of all
network egress, not "allow this destination, block that one." Our own
application layer sinks can do that, since they check the destination
based on data provenance. Genuine filtering by destination at the OS level
would need an actual firewall, such as pfctl, or a filtering proxy, and
neither is built here. Filesystem path scoping does work with genuine
granularity, but macOS resolves /tmp to /private/tmp, and tempfile's
default directory resolves similarly, so profile paths must use the
resolved path or the rule silently does nothing.

The scenario simulates application level provenance enforcement having a
gap, for example a value laundered through .upper() before reaching a
sink. It reads a credentials file and writes its content outside the
declared workspace, with no provenance system involved at all. It runs
twice, once unsandboxed, where the write succeeds, and once sandboxed,
where the OS blocks it independently, with zero concept of provenance. It
only enforces a path boundary.
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
    print("Layer 4 demo: an OS level sandbox as an independent backstop when")
    print("application level provenance enforcement is bypassed entirely.\n")

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
            "Confirmed: the OS level sandbox independently stopped the exfiltration "
            "attempt with zero knowledge of provenance as a concept. It only "
            "enforces a filesystem path boundary, regardless of why a value ended up "
            "outside it."
        )
    else:
        print("WARNING: unexpected result, see the raw output above.")


if __name__ == "__main__":
    main()
