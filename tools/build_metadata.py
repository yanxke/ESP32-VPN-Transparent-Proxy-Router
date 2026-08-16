"""Inject a Git-derived firmware version before PlatformIO compiles the project."""

Import("env")

import subprocess


def git_output(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=env.subst("$PROJECT_DIR"), text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


commit = git_output("rev-parse", "--short=12", "HEAD") or "unknown"
dirty = bool(git_output("status", "--porcelain"))
version = "git-{}{}".format(commit, "-dirty" if dirty else "")
env.Append(CPPDEFINES=[("BUILD_GIT_VERSION", '\\"{}\\"'.format(version))])
print("Firmware version: {}".format(version))
