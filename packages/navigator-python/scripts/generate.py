"""Reproducibly regenerate the private protobuf transport modules."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PROTO = ROOT / "crates/navigator-consumer-protocol/proto"
OUT = ROOT / "packages/navigator-python/src/navigator/_transport"
SOURCE = PROTO / "navigator/consumer/v1/consumer.proto"

OUT.mkdir(parents=True, exist_ok=True)
subprocess.run(
    [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{PROTO}",
        f"--python_out={OUT}",
        f"--grpc_python_out={OUT}",
        f"--pyi_out={OUT}",
        str(SOURCE.relative_to(PROTO)),
    ],
    check=True,
    cwd=PROTO,
)
grpc_module = OUT / "navigator/consumer/v1/consumer_pb2_grpc.py"
grpc_module.write_text(
    grpc_module.read_text().replace(
        "from navigator.consumer.v1 import consumer_pb2",
        "from navigator._transport.navigator.consumer.v1 import consumer_pb2",
    )
)
