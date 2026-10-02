# SPDX-License-Identifier: Apache-2.0
"""How long does it take to start a confined command? hlyn against Docker.

    python3 tools/startbench.py [--rounds N] [--image IMAGE] [--no-docker]

Each round runs every command once, in a fixed order, so slow drift (thermal
throttling, a background job, the Docker VM) lands on all of them. Reports min
and median in milliseconds, nothing rounded in anyone's favour.

  python -c pass             the floor: Python starting and exiting
  hlyn run                   `python3 -m hlyn.cli run --no-log --no-report -- /usr/bin/true`
  hlyn run --net HOST        the same with a host named (the proxy and gate start)
  docker run                 `docker run --rm IMAGE true`
  docker run --network none  the same with no network
  docker exec (warm)         `docker exec CONTAINER true` into a container that
                             is already running: the fairest Docker number for
                             a caller that keeps one container alive

Docker rows are left out when `docker` isn't on the PATH or its daemon doesn't
answer (inside tools/linuxtest.sh the container has no Docker). The image must
already be pulled, except alpine, which is pulled if absent (and said so).

The trap this avoids (FINDINGS.md, "Start-up: what `import hlyn` costs"):
PYTHONDONTWRITEBYTECODE=1 makes a tree recompile every module on every run.
It is removed from the environment of the hlyn runs, and each hlyn command
runs twice, untimed, to warm the bytecode cache first.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HLYN = [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report"]


def hlyn_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
    env["PYTHONPATH"] = str(ROOT / "src")
    return env


def docker(*args: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


def docker_answers() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return docker("info", timeout=30).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def once(argv: list[str], env: dict[str, str]) -> float:
    start = time.perf_counter()
    done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, check=False)
    took = (time.perf_counter() - start) * 1000
    if done.returncode != 0:
        sys.exit(f"{' '.join(argv)} exited {done.returncode}: {done.stderr.decode(errors='replace')[:400]}")
    return took


def machine() -> str:
    lines = [f"{platform.system()} {platform.release()} {platform.machine()}, "
             f"Python {platform.python_version()}"]
    if platform.system() == "Darwin":
        brand = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                               capture_output=True, text=True, check=False)
        lines.append(f"cpu: {brand.stdout.strip()}")
    else:
        for row in Path("/proc/cpuinfo").read_text().splitlines():
            if row.startswith(("model name", "Model", "CPU part")):
                lines.append(f"cpu: {row.split(':', 1)[1].strip()}")
                break
    lines.append(f"cpus: {os.cpu_count()}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Time hlyn's start-up against Docker's.")
    parser.add_argument("--rounds", type=int, default=30,
                        help="rounds, each running every command once (default 30)")
    parser.add_argument("--image", default="alpine", help="a small image already pulled (default alpine)")
    parser.add_argument("--no-docker", action="store_true", help="time only Python and hlyn")
    parser.add_argument("--host", default="example.com",
                        help="the host named for the --net row (default example.com)")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be at least 1")

    plain = dict(os.environ)
    env = hlyn_env()
    commands: dict[str, tuple[list[str], dict[str, str]]] = {
        "python3 -c pass": ([sys.executable, "-c", "pass"], plain),
        "hlyn run": ([*HLYN, "--", "/usr/bin/true"], env),
        f"hlyn run --net {args.host}": ([*HLYN, "--net", args.host, "--", "/usr/bin/true"], env),
    }

    container = None
    note = []
    if not args.no_docker and docker_answers():
        if docker("image", "inspect", args.image).returncode != 0:
            if args.image != "alpine":
                sys.exit(f"{args.image} isn't pulled; pull it yourself or use --image alpine")
            note.append("pulled alpine: it was not present")
            docker("pull", "alpine")
        image = args.image
        commands[f"docker run --rm {image} true"] = (["docker", "run", "--rm", image, "true"], plain)
        commands[f"docker run --rm --network none {image} true"] = (
            ["docker", "run", "--rm", "--network", "none", image, "true"], plain)
        # The container is this script's own, named for it, and removed at the end.
        container = f"hlyn-startbench-{os.getpid()}"
        if docker("run", "-d", "--name", container, image, "sleep", "3600").returncode != 0:
            sys.exit("could not start the container for the docker exec row")
        commands[f"docker exec (warm) {image} true"] = (["docker", "exec", container, "true"], plain)
        ver = docker("version", "--format", "{{.Client.Version}} / server {{.Server.Version}}")
        info = docker("info", "--format", "{{.OperatingSystem}}, kernel {{.KernelVersion}}, {{.NCPU}} cpus")
        note.append(f"docker {ver.stdout.strip()}; VM: {info.stdout.strip()}")
    else:
        why = "--no-docker" if args.no_docker else "no Docker on this machine"
        note.append(f"no Docker rows: {why}")

    try:
        for argv, run_env in commands.values():  # warm: bytecode caches, image layers, the daemon
            once(argv, run_env)
            once(argv, run_env)
        times: dict[str, list[float]] = {name: [] for name in commands}
        for _ in range(args.rounds):
            for name, (argv, run_env) in commands.items():
                times[name].append(once(argv, run_env))
    finally:
        if container:
            docker("rm", "-f", container)

    print(machine())
    for line in note:
        print(line)
    print(f"{args.rounds} rounds, interleaved, 2 untimed warm-up runs each, PYTHONDONTWRITEBYTECODE unset\n")
    width = max(len(name) for name in commands)
    print(f"{'command':<{width}}  {'min ms':>9}  {'median ms':>9}  {'max ms':>9}")
    for name, series in times.items():
        print(f"{name:<{width}}  {min(series):>9.1f}  {statistics.median(series):>9.1f}  {max(series):>9.1f}")


if __name__ == "__main__":
    main()
