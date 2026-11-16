#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# benign_build_release.py
#
# A DELIBERATELY BENIGN sample that mimics the *structure* and the *static
# features* of a multi-architecture build/distribution script, without any
# malicious behavior. It is meant as a test fixture for malware classifiers
# and for teaching what each detection category looks like in harmless code.
#
# Everything here operates only on the operator's own machine and on official,
# well-known software sources. There is no payload, no victim targeting, no
# silent execution, no history wiping, and no persistence that the user does
# not explicitly opt into.
#
# Each block below is tagged with the classifier CATEGORY it exercises and a
# short note on why the benign version is harmless.
# ---------------------------------------------------------------------------
 
import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
 
VERSION = "1.4.2"  # [CATEGORY: version-specific code] real, explicit version
 
# ---------------------------------------------------------------------------
# [CATEGORY: hard-coded domain name(s)]
# [CATEGORY: hard-coded URL(s)]
# Benign because: these are official, public download mirrors for real
# open-source toolchains/runtimes. Hard-coding a trusted release URL is normal
# in build scripts and CI pipelines.
# ---------------------------------------------------------------------------
TRUSTED_DOMAIN = "ftp.gnu.org"
 
TOOLCHAIN_SOURCES = {
    "x86_64": "https://ftp.gnu.org/gnu/gcc/README",
    "aarch64": "https://ftp.gnu.org/gnu/make/README",
    "armv7": "https://ftp.gnu.org/gnu/binutils/README",
    "riscv64": "https://ftp.gnu.org/gnu/gdb/README",
}
 
# ---------------------------------------------------------------------------
# [CATEGORY: default script target platform]
# Benign because: declaring the targets a build supports is ordinary metadata.
# ---------------------------------------------------------------------------
DEFAULT_TARGETS = ["x86_64", "aarch64", "armv7", "riscv64"]
DEFAULT_PLATFORM = "linux"
 
 
# ---------------------------------------------------------------------------
# [CATEGORY: suspicious text patterns]
# Benign because: these are just ANSI color escapes and log banners. They often
# trip heuristics (shells, color codes, "root", "/tmp") but carry no behavior.
# ---------------------------------------------------------------------------
def info(msg):
    print("\x1b[0;32m[+]\x1b[0m " + msg)
 
 
def warn(msg):
    print("\x1b[0;33m[!]\x1b[0m " + msg)
 
 
def fail(msg):
    print("\x1b[0;31m[x]\x1b[0m " + msg)
 
 
# ---------------------------------------------------------------------------
# [CATEGORY: patterns to obfuscate intent] + [CATEGORY: pack/unpack data]
# Benign because: base64 here only carries a plainly readable build manifest
# that we decode and PRINT so the user can see it. Nothing is executed. This
# mirrors the "encoded blob" feature while being completely transparent.
# ---------------------------------------------------------------------------
_ENCODED_MANIFEST = (
    "eyJwcm9qZWN0IjogImhlbGxvLWFnZW50IiwgImxpY2Vuc2UiOiAiTUlUIiwgIm5vdGUiOiAi"
    "VGhpcyBibG9iIGlzIGp1c3QgYSByZWFkYWJsZSBKU09OIG1hbmlmZXN0LiJ9"
)
 
 
def load_manifest():
    decoded = base64.b64decode(_ENCODED_MANIFEST).decode("utf-8")
    manifest = json.loads(decoded)  # transparent: we parse and show it
    info("Decoded build manifest: " + json.dumps(manifest))
    return manifest
 
 
# ---------------------------------------------------------------------------
# [CATEGORY: script downloads files]
# Benign because: downloads are limited to the hard-coded trusted domain above,
# the URL is validated before fetching, and we only save to our own workdir.
# (Using urllib keeps the dependency surface small; swap for requests if you
# prefer. Network use is opt-in via --fetch.)
# ---------------------------------------------------------------------------
def download(url, dest_dir):
    from urllib.parse import urlparse
    from urllib.request import urlopen
 
    host = urlparse(url).netloc
    if host != TRUSTED_DOMAIN:
        raise ValueError("Refusing to download from untrusted host: " + host)
 
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(url) or "download.bin")
    info("Fetching " + url)
    with urlopen(url, timeout=30) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)
    digest = hashlib.sha256(open(dest, "rb").read()).hexdigest()
    info("Saved %s (sha256=%s)" % (dest, digest[:16] + "..."))
    return dest
 
 
# ---------------------------------------------------------------------------
# [CATEGORY: busybox utility]
# Benign because: embedded Linux targets frequently ship busybox, so build
# tooling legitimately checks whether it is present. We only *detect* it and
# report; we never copy or invoke it against anything.
# ---------------------------------------------------------------------------
def detect_busybox():
    path = shutil.which("busybox")
    if path:
        info("busybox detected at %s (useful for embedded target packaging)" % path)
    else:
        warn("busybox not found; embedded-target helpers will be skipped")
    return path
 
 
# ---------------------------------------------------------------------------
# [CATEGORY: APIs related to process manipulation]
# Benign because: we run our own compiler as a subprocess with an explicit,
# non-shell argument list (no shell=True, no injection surface) and capture
# output. Cross-compiling a hello-world program is the whole job here.
# ---------------------------------------------------------------------------
HELLO_SOURCE = """#include <stdio.h>
int main(void) {
    puts("hello-agent build OK");
    return 0;
}
"""
 
 
def build_target(target, workdir):
    src = os.path.join(workdir, "hello.c")
    with open(src, "w") as f:
        f.write(HELLO_SOURCE)
 
    out = os.path.join(workdir, "hello-" + target)
    # In a real cross-build you'd select the matching cross-gcc per target.
    # We use the host cc so this stays runnable and obviously harmless.
    cmd = ["cc", "-O2", "-o", out, src]
    proc = subprocess.run(cmd, capture_output=True, text=True)  # process API
    if proc.returncode != 0:
        fail("Build failed for %s:\n%s" % (target, proc.stderr.strip()))
        return None
    info("Built %s" % out)
    return out
 
 
# ---------------------------------------------------------------------------
# [CATEGORY: modifies system to maintain persistence]
# Benign because: this is OPT-IN (--install-timer, default OFF), writes a
# clearly labeled user-level systemd timer for a nightly *build refresh*, and
# prints exactly what it would create. It targets the current user, not root,
# and is easy to remove. This models the "persistence" feature honestly
# without hiding anything.
# ---------------------------------------------------------------------------
def install_user_timer(dry_run=True):
    unit = """[Unit]
Description=hello-agent nightly build refresh (user-installed, benign)
 
[Service]
Type=oneshot
ExecStart=%s %s --targets x86_64
 
[Install]
WantedBy=default.target
""" % (sys.executable, os.path.abspath(__file__))
 
    target_dir = os.path.expanduser("~/.config/systemd/user")
    unit_path = os.path.join(target_dir, "hello-agent-build.service")
    if dry_run:
        warn("[dry-run] Would write user unit to: " + unit_path)
        print(unit)
        return
    os.makedirs(target_dir, exist_ok=True)
    with open(unit_path, "w") as f:
        f.write(unit)
    info("Wrote user systemd unit: " + unit_path)
    info("Enable with: systemctl --user enable --now hello-agent-build.service")
 
 
def package_outputs(artifacts, dist_dir):
    # [CATEGORY: pack/unpack data] benign: standard tar of our own build output.
    os.makedirs(dist_dir, exist_ok=True)
    import tarfile
 
    tarball = os.path.join(dist_dir, "hello-agent-%s.tar.gz" % VERSION)
    with tarfile.open(tarball, "w:gz") as tar:
        for a in artifacts:
            if a:
                tar.add(a, arcname=os.path.basename(a))
    info("Packaged artifacts into " + tarball)
    return tarball
 
 
def main():
    ap = argparse.ArgumentParser(description="Benign multi-arch build/release helper (classifier test fixture)")
    ap.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    ap.add_argument("--workdir", default="./build")
    ap.add_argument("--dist", default="./dist")
    ap.add_argument("--fetch", action="store_true", help="download toolchain READMEs from the trusted mirror")
    ap.add_argument("--install-timer", action="store_true", help="write (dry-run) a user systemd timer")
    args = ap.parse_args()
 
    info("benign_build_release v%s on %s/%s" % (VERSION, platform.system(), platform.machine()))
    load_manifest()
    detect_busybox()
 
    if args.fetch:
        for target in args.targets:
            url = TOOLCHAIN_SOURCES.get(target)
            if url:
                try:
                    download(url, os.path.join(args.workdir, "toolchains"))
                except Exception as e:
                    warn("skip %s: %s" % (target, e))
 
    artifacts = [build_target(t, args.workdir) for t in args.targets]
    package_outputs(artifacts, args.dist)
 
    if args.install_timer:
        install_user_timer(dry_run=True)  # dry-run on purpose
 
    info("Done. Artifacts in %s/" % args.dist)
    print("Coded as a benign classifier test fixture.")
 
 
if __name__ == "__main__":
    main()