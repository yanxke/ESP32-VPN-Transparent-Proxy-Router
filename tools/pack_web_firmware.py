"""Create the single ESP32-S3 image used by the browser-based web flasher."""

Import("env")

import os
import shutil
import subprocess
import zipfile


def git_version(project_dir):
    """Return the release filename version matching the embedded Git version."""
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"],
                                         cwd=project_dir, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"],
                                              cwd=project_dir, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        return "git-unknown"
    return "git-{}{}".format(commit, "-dirty" if dirty else "")


def pack_web_firmware(source, target, env):
    build_dir = env.subst("$BUILD_DIR")
    project_dir = env.subst("$PROJECT_DIR")
    env_name = env.subst("$PIOENV")
    package_dir = env.PioPlatform().get_package_dir("tool-esptoolpy")
    output_dir = os.path.join(project_dir, "dist")
    output_basename = "esp32-vless-router-{}".format(env_name)
    output_file = os.path.join(output_dir, output_basename + ".bin")
    ota_file = os.path.join(output_dir, output_basename + "-ota.bin")
    archive_file = os.path.join(output_dir, "{}-{}.zip".format(
        output_basename, git_version(project_dir)))
    instructions = os.path.join(project_dir, "docs", "WEB_FLASHING.md")
    bootloader = os.path.join(build_dir, "bootloader.bin")
    partitions = os.path.join(build_dir, "partitions.bin")
    firmware = env.subst("$BUILD_DIR/${PROGNAME}.bin")
    esptool = os.path.join(package_dir, "esptool.py")

    required = (bootloader, partitions, firmware, esptool, instructions)
    missing = [path for path in required if not os.path.isfile(path)]
    if missing:
        raise RuntimeError("Cannot create web-flash image; missing: " + ", ".join(missing))

    os.makedirs(output_dir, exist_ok=True)
    command = [
        env.subst("$PYTHONEXE"),
        esptool,
        "--chip",
        "esp32s3",
        "merge_bin",
        "-o",
        output_file,
        "0x0",
        bootloader,
        "0x8000",
        partitions,
        "0x20000",
        firmware,
    ]
    subprocess.run(command, check=True)
    print("Web-flash image: {} (flash at 0x0)".format(output_file))
    shutil.copyfile(firmware, ota_file)
    print("OTA image: {} (upload through the authenticated portal)".format(ota_file))
    with zipfile.ZipFile(archive_file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(output_file, os.path.basename(output_file))
        archive.write(ota_file, os.path.basename(ota_file))
        archive.write(instructions, "WEB_FLASHING.md")
    print("Release archive: {}".format(archive_file))


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", pack_web_firmware)
