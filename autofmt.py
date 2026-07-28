#!/usr/bin/python3

import os
import pathlib
import stat
import subprocess
import sys

key6_root = pathlib.Path(__file__).parent.resolve()
autofmt_root = key6_root / "autofmt"
autofmt_binary = autofmt_root / "zig-out" / "bin" / "autofmt"
autofmt_binary_as_posix = autofmt_binary.as_posix()

def runSubprocess(
  *,
  cwd: pathlib.Path,
  forwards_stdout: bool,
  arguments: list[str]
):
    process = subprocess.run(arguments, capture_output=True, cwd=cwd, text=True)
    if (forwards_stdout):
        print(process.stdout[:-1])
    if (process.returncode != 0):
        if (process.stderr):
            print(process.stderr, file=sys.stderr)
        process.check_returncode()

runSubprocess(cwd=autofmt_root, forwards_stdout=False, arguments=[
  "zig",
  "fetch",
  "https://github.com/Hejsil/zig-clap/archive/refs/tags/0.12.0.tar.gz"
])
runSubprocess(cwd=autofmt_root, forwards_stdout=False, arguments=["zig", "build"])
os.chmod(
  autofmt_binary_as_posix,
  os.stat(autofmt_binary_as_posix).st_mode | stat.S_IXUSR
)
runSubprocess(cwd=key6_root, forwards_stdout=True, arguments=[
    autofmt_binary.relative_to(key6_root).as_posix(),
    *sys.argv[1:]
])
