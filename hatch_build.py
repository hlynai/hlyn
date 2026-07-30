"""Put the native shim inside the wheel.

The Linux backend reaches Landlock through a small Rust shim, and `landlock.py`
looks for it next to the package before falling back to a build tree. So a
wheel that does not carry it installs cleanly and then refuses to confine
anything, which is the failure this project exists to avoid.

macOS needs nothing here: Seatbelt is reached through the system library, so
those wheels are pure Python.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

ROOT = Path(__file__).parent
CRATE = ROOT / "native"
BUILT = CRATE / "target" / "release" / "libhlyn.so"
INSIDE = ROOT / "src" / "hlyn" / "core" / "libhlyn.so"


class CustomBuildHook(BuildHookInterface):  # type: ignore[type-arg]
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if sys.platform != "linux":
            return

        if not BUILT.exists():
            cargo = shutil.which("cargo")
            if cargo is None:
                raise RuntimeError(
                    f"the Landlock shim is missing ({BUILT}) and cargo is not "
                    "installed, so it cannot be built. Install a Rust toolchain, "
                    "or build the shim first with `cargo build --release` in "
                    "native/. Refusing to produce a wheel that installs and then "
                    "cannot confine anything."
                )
            # Resolved rather than named, so the build does not depend on what
            # PATH happens to mean when the backend runs. Nothing here comes
            # from outside: the executable is what `which` found and the
            # arguments are fixed.
            subprocess.run([cargo, "build", "--release"], cwd=CRATE, check=True)  # noqa: S603

        INSIDE.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(BUILT, INSIDE)

        # The wheel now holds a compiled object, so it is not portable to
        # another platform and must not claim to be: pip would install it on a
        # machine that cannot load it.
        build_data["pure_python"] = False
        build_data["artifacts"].append("/src/hlyn/core/libhlyn.so")

        # Platform-specific but not interpreter-specific. The shim is loaded
        # through ctypes and links against nothing in libpython, so it works on
        # every supported Python and a per-version wheel would be three extra
        # builds saying the same thing. Left to `infer_tag`, hatchling would
        # stamp it cp313-cp313 because the wheel stopped being pure Python.
        machine = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        build_data["tag"] = f"py3-none-{machine}"
