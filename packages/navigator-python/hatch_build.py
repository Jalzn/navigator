import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        del version
        if self.target_name == "wheel":
            runtime = Path(self.root) / "src/navigator/_runtime"
            manifest = json.loads((runtime / "manifest.json").read_text(encoding="ascii"))
            if manifest.get("version") != 2 or set(manifest.get("artifacts", {})) != {
                "darwin-arm64"
            }:
                raise RuntimeError("prepare_runtime.py must create a darwin-arm64 manifest v2")
            target = manifest["artifacts"]["darwin-arm64"]
            if target.get("driver_id") != "00000000000000000000000000000001":
                raise RuntimeError("runtime manifest has an unexpected Pi driver identity")
            records = [
                target[name]
                for name in ("navigatord", "node", "acceptance_provider")
            ]
            records.extend(target["pi_tree"])
            if target["pi_entrypoint"] not in target["pi_tree"]:
                raise RuntimeError("Pi entrypoint is not represented in the complete Pi tree")
            paths: set[str] = set()
            for record in records:
                relative = PurePosixPath(record["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError(f"unsafe runtime path: {relative}")
                if relative.as_posix() in paths:
                    raise RuntimeError(f"duplicate runtime path: {relative}")
                paths.add(relative.as_posix())
                artifact = runtime.joinpath(*relative.parts)
                if not artifact.is_file() or artifact.stat().st_size != record["size"]:
                    raise RuntimeError(f"missing or stale runtime artifact: {relative}")
                if hashlib.sha256(artifact.read_bytes()).hexdigest() != record["sha256"]:
                    raise RuntimeError(f"runtime digest mismatch: {relative}")
            recorded_pi = {record["path"] for record in target["pi_tree"]}
            actual_pi = {
                path.relative_to(runtime).as_posix()
                for path in runtime.joinpath("darwin-arm64/pi").rglob("*")
                if path.is_file()
            }
            if recorded_pi != actual_pi:
                raise RuntimeError("runtime Pi tree is not completely represented in the manifest")
            build_data["tag"] = "py3-none-macosx_11_0_arm64"
