#!/usr/bin/env python3

import os
import pathlib
import sys


root = pathlib.Path(sys.argv[1])
run = pathlib.Path(sys.argv[2])
pending = root / f".latest.{os.getpid()}"
pending.symlink_to(run.name)
os.replace(pending, root / "latest")
