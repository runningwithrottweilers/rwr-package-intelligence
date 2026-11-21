#!/usr/bin/env python3
"""Run compatibility regressions without host authority, networking or a display.

Input is Cargo's --no-run --message-format=json output. Compilation is separate;
the selected tests never request an ALPM COMMIT. bwrap failure is a hard failure.
"""
import argparse
import json
from pathlib import Path
import subprocess


LIB_FILTERS = (
    "libalpm_ffi::signature_tests::",
    "libalpm_ffi::https_execution_policy_tests::",
    "libalpm_ffi::execution_question_routing_tests::",
    "production_alpm_flow::policy_purpose_tests::",
    "production_alpm_flow::polkit_check_id_tests::",
    "production_alpm_flow::polkit_decision_binding_tests::",
    "production_alpm_flow::plan_commitment_diagnostics::",
    "production_alpm_flow::semantic_plan_commitment_tests::",
    "supervisor_trust::execution_policy_tests::",
    "test_isolation::",
    "transaction_ipc::",
    "transaction_protocol::",
)
GUI_FILTERS = (
    "classification::", "intelligence::", "packages::", "changelog::",
    "changelog_sources::", "changelog_fetch::", "change_items::",
    "update_analysis::", "update_cards::", "ui::", "production_ipc::",
    "ufo_progress::",
)
DISPLAY_TESTS = (
    "ui::real_mode_label_tests::refresh_targets_real_mode_label_not_prepended_supervisor_label",
    "ui::structured_plan_review_tests::shows_real_plan_fields_and_expandable_dependencies_in_both_languages",
)
INTEGRATION_TARGETS = (
    "ipc_helper_integration", "production_helper_integration",
    "production_helper_ipc", "supervisor_reconnect_integration",
    "confirmed_plan_helper_supervisor", "diagnostic_supervisor_e2e",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    artifacts = []
    for line in args.artifacts.read_text().splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if value.get("executable") and value.get("profile", {}).get("test"):
            artifacts.append(value)
    if not artifacts:
        raise SystemExit("No test executables in Cargo artifact manifest")
    # Keep compiled binaries reachable while masking all other /tmp contents.
    target = Path(artifacts[0]["executable"]).resolve()
    while target.name != "debug" and target != target.parent:
        target = target.parent
    if target.name != "debug":
        raise SystemExit("Expected a debug Cargo target directory")
    target = target.parent
    sandbox = [
        "bwrap", "--unshare-all", "--die-with-parent", "--new-session",
        "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--chmod", "0755", "/tmp", "--dir", str(target),
        "--ro-bind", str(target), str(target),
        "--tmpfs", "/run", "--tmpfs", "/var/lib/pacman",
        "--tmpfs", "/etc/rwr-package-intelligence",
        "--dir", "/tmp/rwr-home", "--setenv", "HOME", "/tmp/rwr-home",
        "--setenv", "RWR_TEST_ISOLATION", "1",
        "--setenv", "DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent",
        "--setenv", "DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent",
        "--unsetenv", "DISPLAY", "--unsetenv", "WAYLAND_DISPLAY",
        "--unsetenv", "AT_SPI_BUS_ADDRESS", "--chdir", str(root),
    ]
    results = []
    for artifact in artifacts:
        name = artifact["target"]["name"]
        kind = artifact["target"]["kind"]
        if kind == ["lib"]:
            filters = LIB_FILTERS
        elif name == "rwr-package-intelligence":
            filters = GUI_FILTERS
        elif name in INTEGRATION_TARGETS:
            filters = ()  # These integration targets exercise refusal/IPC only.
        else:
            continue
        command = sandbox + [artifact["executable"], *filters, "--test-threads=1"]
        if name == "rwr-package-intelligence":
            for test in DISPLAY_TESTS:
                command.extend(["--skip", test])
            print("Display-dependent tests excluded:", ", ".join(DISPLAY_TESTS), flush=True)
        run = subprocess.run(command, capture_output=True, text=True, timeout=180)
        result = dict(target=name, kind=kind, exit_code=run.returncode,
                      stdout=run.stdout, stderr=run.stderr)
        results.append(result)
        summary = [line for line in run.stdout.splitlines()
                   if line.startswith("test result:")]
        print(name, summary or run.stderr.strip(), flush=True)
        if run.returncode:
            print(run.stdout[-4000:], run.stderr[-1000:], flush=True)
    args.report.write_text(json.dumps(results, indent=2))
    if len(results) != 2 + len(INTEGRATION_TARGETS):
        raise SystemExit("Missing expected compatibility test targets")
    raise SystemExit(any(result["exit_code"] for result in results))


if __name__ == "__main__":
    main()
