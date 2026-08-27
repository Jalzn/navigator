#!/usr/bin/env python3

import fcntl
import os
import pathlib
import sys


if len(sys.argv) < 2:
    raise SystemExit("usage: with-source-gate-lock.py COMMAND [ARG ...]")

project_root = pathlib.Path(__file__).resolve().parent.parent
lock_path = project_root / "target" / "conformance" / "source-gates.lock"
lock_path.parent.mkdir(parents=True, exist_ok=True)

with lock_path.open("a+b") as lock_file:
    fcntl.flock(lock_file, fcntl.LOCK_EX)
    os.set_inheritable(lock_file.fileno(), True)
    os.chdir(project_root)
    os.execvp(sys.argv[1], sys.argv[1:])
