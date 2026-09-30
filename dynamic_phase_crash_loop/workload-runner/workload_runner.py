#!/usr/bin/env python3
"""
workload_runner.py — starts a target container under a given seccomp profile,
waits for it to be ready, drives the matching benchmark tool (wrk /
redis-benchmark / sysbench) against it from a sidecar "tools" container on the
same Docker network, and tears everything down.

Designed to be called as the --test-cmd hook of the seccomp discovery loop:
each invocation = one "pass" that generates real traffic for Tracee to capture.

Usage:
    python3 workload_runner.py \
        --image redis:7 \
        --seccomp-profile ./candidate.json \
        --config workloads.yaml \
        [--env KEY=VALUE ...] [--timeout 60]

Exit code 0 = workload completed successfully.
Exit code 1 = no matching workload found, container never became ready, or the
              benchmark itself failed. The caller (discovery loop) should treat
              a non-zero exit as "this profile is not sufficient yet" only when
              paired with new Tracee events — a benchmark failure alone could
              also mean the workload itself is misconfigured, so log enough
              detail to tell the two apart.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
import uuid
import yaml


def load_registry(config_path):
    with open(config_path) as f:
        data = yaml.safe_load(f)
    return data["workloads"]


def match_workload(image, registry):
    for entry in registry:
        if re.search(entry["match"], image, re.IGNORECASE):
            return entry
    return None


def run(cmd, **kwargs):
    print(f"+ {cmd}", file=sys.stderr)
    return subprocess.run(cmd, shell=True, text=True,
                           capture_output=True, **kwargs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="target image, e.g. redis:7")
    ap.add_argument("--seccomp-profile", required=True,
                     help="path to the seccomp JSON profile to apply")
    ap.add_argument("--config", default="workloads.yaml")
    ap.add_argument("--env", action="append", default=[],
                     help="extra -e KEY=VALUE for the target container")
    ap.add_argument("--timeout", type=int, default=60,
                     help="seconds to wait for the target to become ready")
    ap.add_argument("--workload-timeout", type=int, default=90,
                     help="maximum seconds for prepare, benchmark, and cleanup")
    ap.add_argument("--prepare-retries", type=int, default=5,
                     help="number of retries for the optional prepare step")
    ap.add_argument("--metadata-file", default=None,
                     help="write target container identity for Tracee filtering")
    ap.add_argument("--network", default="seccomp-discovery-net")
    args = ap.parse_args()

    registry = load_registry(args.config)
    entry = match_workload(args.image, registry)
    if entry is None:
        print(f"No workload registered for image '{args.image}'. "
              f"Add an entry to {args.config}.", file=sys.stderr)
        sys.exit(1)

    run_id = uuid.uuid4().hex[:8]
    target_name = f"seccomp-target-{run_id}"
    port = entry["port"]

    # Ensure the shared network exists (idempotent).
    run(f"docker network create {args.network} 2>/dev/null || true")

    env_flags = " ".join(f"-e {e}" for e in args.env)

    try:
        # --- Start target container under the candidate seccomp profile ---
        start = run(
            f"docker run -d --rm --name {target_name} "
            f"--network {args.network} --network-alias {target_name} "
            f'--security-opt seccomp="{args.seccomp_profile}" '
            f"--security-opt=no-new-privileges "
            f"{env_flags} {args.image}"
        )
        if start.returncode != 0:
            print(f"Failed to start target container:\n{start.stderr}",
                  file=sys.stderr)
            sys.exit(1)

        if args.metadata_file:
            inspect = run(
                f"docker inspect --format '{{{{.Id}}}}' {target_name}"
            )
            if inspect.returncode != 0:
                print(f"Failed to inspect target container:\n{inspect.stderr}",
                      file=sys.stderr)
                sys.exit(1)
            identity = inspect.stdout.strip().split()
            if len(identity) != 1 or not identity[0]:
                print(f"Could not determine target identity: {inspect.stdout}",
                      file=sys.stderr)
                sys.exit(1)
            with open(args.metadata_file, "w", encoding="utf-8") as metadata:
                json.dump({"container_id": identity[0]}, metadata)

        # --- Wait for readiness ---
        # Note: readiness is checked from *this* host by resolving the
        # container's mapped port isn't set up here (no -p was used, since
        # the tools container reaches it directly via the docker network
        # alias). If you need host-side readiness checks too, add -p and
        # check localhost instead.
        ready = _wait_ready_via_tools_container(
            target_name, port, args.network, args.timeout
        )
        if not ready:
            print(f"Target '{target_name}' did not become ready within "
                  f"{args.timeout}s", file=sys.stderr)
            _dump_logs(target_name)
            sys.exit(1)

        # --- Optional prepare step (e.g. sysbench table setup) ---
        if "prepare_cmd" in entry:
            cmd = entry["prepare_cmd"].format(host=target_name, port=port)
            result = None
            for attempt in range(args.prepare_retries):
                result = _exec_in_tools_container(entry, cmd, args.network,
                                                  args.workload_timeout)
                if result.returncode == 0:
                    break
                if attempt + 1 < args.prepare_retries:
                    time.sleep(5)
            if result.returncode != 0:
                print(
                    f"Prepare step failed:\n{result.stdout}\n{result.stderr}",
                    file=sys.stderr,
                )
                _dump_logs(target_name)
                sys.exit(1)

        # --- Run the benchmark ---
        bench_cmd = entry["bench_cmd"].format(host=target_name, port=port)
        result = _exec_in_tools_container(entry, bench_cmd, args.network,
                          args.workload_timeout)
        print(result.stdout)
        if result.returncode != 0:
            print(f"Benchmark failed:\n{result.stderr}", file=sys.stderr)
            _dump_logs(target_name)
            sys.exit(1)

        # --- Optional cleanup step ---
        if "cleanup_cmd" in entry:
            cmd = entry["cleanup_cmd"].format(host=target_name, port=port)
            _exec_in_tools_container(entry, cmd, args.network,
                                     args.workload_timeout)

        print(f"Workload '{entry['tool']}' against '{args.image}' "
              f"completed successfully.")
        sys.exit(0)

    finally:
        # Always tear down the target so it doesn't leak between iterations
        # of the discovery loop.
        run(f"docker stop {target_name} 2>/dev/null || true")


def _exec_in_tools_container(entry, command, network, timeout):
    tool_run_id = uuid.uuid4().hex[:8]
    if entry.get("shell", True):
        tool_command = f"sh -c {shlex.quote(command)}"
    else:
        tool_command = shlex.join(shlex.split(command))
    try:
        return run(
            f"docker run --rm --name tools-{tool_run_id} "
            f"--network {network} {entry['tool_image']} "
            f"{tool_command}",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        run(f"docker rm -f tools-{tool_run_id} 2>/dev/null || true")
        return subprocess.CompletedProcess(
            args=exc.cmd, returncode=124, stdout="", stderr="tool timed out"
        )


def _wait_ready_via_tools_container(target_name, port, network, timeout):
    """
    Use a throwaway busybox/netcat container on the same network to test
    connectivity to the target's alias, since the host may not have a
    route to the container's internal network.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = run(
            f"docker run --rm --network {network} busybox "
            f"nc -z -w 2 {target_name} {port}"
        )
        if result.returncode == 0:
            return True
        time.sleep(1.5)
    return False


def _dump_logs(container_name):
    logs = run(f"docker logs {container_name}")
    print("--- target container logs ---", file=sys.stderr)
    print(logs.stdout, file=sys.stderr)
    print(logs.stderr, file=sys.stderr)


if __name__ == "__main__":
    main()
