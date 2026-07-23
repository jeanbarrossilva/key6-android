#!/usr/bin/python3

from pathlib import Path
from sys import argv, stderr
import subprocess

if __name__ == '__main__':
  autofmt_dir = Path(__file__).parent.resolve() / "autofmt"
  zig_fetch = subprocess.run(
    [
      "zig",
      "fetch",
      "https://github.com/Hejsil/zig-clap/archive/refs/tags/<REPLACE ME>.tar.gz"
    ],
    capture_output=True,
    cwd=autofmt_dir,
    text=True
  )
  zig_build = subprocess.run(
    ["zig", "build"],
    capture_output=True,
    cwd=autofmt_dir,
    text=True
  )
  if (zig_build.returncode != 0):
    print(zig_build.stderr, file=stderr)
    zig_build.check_returncode()
  autofmt = subprocess.run(
    ["./autofmt", *argv[1:]],
    capture_output = True,
    cwd=autofmt_dir / "zig-out" / "bin",
    text=True
  )
  if (autofmt.returncode == 0):
    print(autofmt.stdout)
  else:
    print(autofmt.stderr, file=stderr)
    autofmt.check_returncode()
