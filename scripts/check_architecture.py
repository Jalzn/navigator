#!/usr/bin/env python3

import json
import subprocess
import sys

rules = {
    "navigator-domain": {
        "proptest", "serde", "serde_json", "sha2", "static_assertions",
        "thiserror", "time", "uuid",
    },
    "navigator-protocol": {
        "navigator-domain", "proptest", "serde", "serde_json", "thiserror", "uuid",
    },
    "navigator-conformance": {
        "navigator-domain", "navigator-store-api", "proptest", "serde", "serde_json", "time", "tokio", "uuid",
    },
    "navigator-store-api": {
        "navigator-domain", "proptest", "serde", "serde_json", "thiserror", "time", "uuid",
    },
    "navigator-store-sqlite": {
        "hmac", "navigator-conformance", "navigator-domain", "navigator-store-api", "proptest", "serde", "serde_json", "sqlx",
        "sha2", "tempfile", "thiserror", "time", "tokio", "tracing", "uuid",
    },
    "navigator-core": {
        "navigator-domain", "navigator-store-api", "thiserror", "time", "tokio", "uuid",
    },
    "navigator-supervisor": {
        "command-fds", "hmac", "navigator-domain", "navigator-driver-client", "navigator-driver-protocol", "navigator-store-api", "navigator-store-sqlite", "nix", "sha2", "subtle",
        "tempfile", "thiserror", "time", "tokio", "uuid",
    },
    "navigator-consumer-protocol": {
        "navigator-domain", "prost", "prost-types", "protoc-bin-vendored", "thiserror", "tonic", "tonic-prost", "tonic-prost-build", "uuid",
    },
    "navigator-driver-protocol": {
        "hmac", "prost", "prost-types", "proptest", "protoc-bin-vendored", "serde_json", "sha2", "subtle",
        "thiserror", "tonic-prost-build",
    },
    "navigator-driver-client": {
        "navigator-driver-protocol", "prost", "sha2", "tempfile", "thiserror",
    },
    "navigator-driver-fake": {
        "command-fds", "navigator-conformance", "navigator-consumer-protocol", "navigator-core", "navigator-domain", "navigator-driver-client", "navigator-driver-protocol", "nix",
        "navigator-local", "navigator-store-api", "navigator-store-sqlite", "navigator-supervisor", "prost", "serde", "serde_json",
        "sha2", "sqlx", "tempfile", "thiserror", "time", "tokio", "uuid",
    },
    "navigator-local": {
        "clap", "navigator-consumer-protocol", "navigator-core", "navigator-domain",
        "navigator-driver-client", "navigator-driver-protocol", "navigator-supervisor",
        "navigator-store-api", "navigator-store-sqlite", "nix", "serde", "serde_json", "sha2", "subtle", "tempfile", "thiserror", "tokio",
        "prost", "sqlx", "time", "tokio-stream", "tonic", "uuid",
    },
}

dev_only = {
    "navigator-driver-fake": {"sqlx"},
    "navigator-local": {"prost"},
}


def load_metadata() -> dict[str, object]:
    return json.loads(
        subprocess.check_output(
            [
                "mise", "exec", "--", "cargo", "metadata", "--no-deps",
                "--format-version", "1",
            ],
            text=True,
        )
    )


def validate(metadata: dict[str, object]) -> list[str]:
    dependencies: dict[str, dict[str, set[str]]] = {}
    for package in metadata["packages"]:  # type: ignore[index]
        by_name: dict[str, set[str]] = {}
        for dependency in package["dependencies"]:
            kind = dependency.get("kind") or "normal"
            by_name.setdefault(dependency["name"], set()).add(kind)
        dependencies[package["name"]] = by_name

    violations = []
    unreviewed_packages = set(dependencies) - set(rules)
    if unreviewed_packages:
        violations.append(
            f"workspace packages have no architecture rule: {sorted(unreviewed_packages)}"
        )
    for package, allowed in rules.items():
        actual = set(dependencies.get(package, {}))
        unexpected = actual - allowed
        if unexpected:
            violations.append(
                f"{package} depends on unreviewed crates: {sorted(unexpected)}"
            )
        for dependency in dev_only.get(package, set()):
            kinds = dependencies.get(package, {}).get(dependency, set())
            if kinds and kinds != {"dev"}:
                violations.append(
                    f"{package} may depend on {dependency} only as a dev-dependency; "
                    f"observed kinds: {sorted(kinds)}"
                )
    return violations


def main() -> int:
    violations = validate(load_metadata())
    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("workspace dependency direction: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
