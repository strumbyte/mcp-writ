#!/usr/bin/env bash
# PR-16 host-setup prototype: Kata Containers on WSL2 (Ubuntu 24.04).
#
# Reproduces the environment used for docs/validation/kata.md. Review
# each step before running — this changes host state (packages, a loadable
# kernel module, a systemd unit, dockerd config). All steps are
# reversible; the removal notes are at the bottom.
#
#   sudo bash setup-wsl2.sh            # run all steps
#   sudo bash setup-wsl2.sh vsock      # only the vhost-vsock workaround
set -euo pipefail

KATA_VER=4.2.0
KATA_TARBALL_SHA256=b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8
# QEMU/guest bits ship inside the static tarball; nothing else is pinned
# here — record what you actually deployed in docs/validation/kata.md.

step="${1:-all}"

# ─── 1. Docker ────────────────────────────────────────────────────────
# docker.io is enough; Docker >= 26 drives Kata via the containerd shim
# (runtimeType io.containerd.kata.v2).
docker_setup() {
    apt-get update
    apt-get install -y docker.io
    systemctl enable --now docker
}

# ─── 2. Kata static release ───────────────────────────────────────────
kata_setup() {
    apt-get install -y zstd curl
    cd /tmp
    curl -fLO "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VER}/kata-static-${KATA_VER}-amd64.tar.zst"
    echo "${KATA_TARBALL_SHA256}  kata-static-${KATA_VER}-amd64.tar.zst" | sha256sum -c -
    tar -xf "kata-static-${KATA_VER}-amd64.tar.zst" -C /

    # runtime-rs + QEMU config; trim guest memory for a small host.
    # runtime-rs configs live under the runtime-rs/ subdirectory.
    mkdir -p /etc/kata-containers
    cp /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml \
       /etc/kata-containers/configuration.toml
    sed -i 's/^default_memory = .*/default_memory = 1024/' \
        /etc/kata-containers/configuration.toml

    # Register the runtime-rs shim with dockerd. runtimeType takes the
    # shim binary path — a bare "io.containerd.kata.v2" type name only
    # resolves if containerd-shim-kata-v2 is on dockerd's PATH.
    mkdir -p /etc/docker
    python3 - <<'EOF' || true
import json, os
p = "/etc/docker/daemon.json"
d = json.load(open(p)) if os.path.exists(p) else {}
d.setdefault("runtimes", {})["kata"] = {
    "runtimeType": "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2",
}
d["runtimes"]["kata"].pop("path", None)  # mutually exclusive with runtimeType
d["runtimes"]["kata"].setdefault("options", {})["ConfigPath"] = "/etc/kata-containers/configuration.toml"
open(p, "w").write(json.dumps(d, indent=2) + "\n")
EOF
    systemctl restart docker
}

# ─── 3. /dev/vhost-vsock workaround (WSL2 5.15 lacks it) ──────────────
# WSL2's stock kernel (5.15.167.4-microsoft-standard-WSL2) is built with
# CONFIG_VHOST_VSOCK unset, and Kata 4.x has no proxy fallback — vhost
# vsock is mandatory. We build the module from the matching kernel source
# tag and load it via a oneshot unit (the /lib/modules tree is rebuilt at
# every WSL boot, so depmod alone does not persist).
vsock_setup() {
    [ -e /dev/vhost-vsock ] && { echo "/dev/vhost-vsock already present"; return 0; }
    local kver ktag src
    kver="$(uname -r)"                                   # e.g. 5.15.167.4-microsoft-standard-WSL2
    ktag="linux-msft-wsl-${kver%-*}"                      # strip -microsoft-standard-WSL2
    src="/root/wsl2-kernel"
    apt-get install -y git build-essential flex bison libssl-dev libelf-dev dwarves bc
    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$ktag" \
            https://github.com/microsoft/WSL2-Linux-Kernel "$src"
    fi
    # Use the running kernel's config when exposed; fall back to the
    # in-tree WSL defconfig. zcat writes $src/.config directly so a
    # failure can't leave a stale copy.
    zcat /proc/config.gz > "$src/.config" 2>/dev/null || \
        cp "$src/arch/x86/configs/config-wsl" "$src/.config"
    (cd "$src" && make olddefconfig && \
     # Only the two missing options need flipping to =m: VSOCK and VHOST
     # are already built-in (=y) on the WSL kernel — forcing them to =m
     # would invalidate the build.
     ./scripts/config --module VHOST_VSOCK \
         --module VMWARE_VSOCKETS_VIRTIO_TRANSPORT_COMMON && \
     make olddefconfig && make modules_prepare && \
     # Build each dir with its own `make M=` (a second M= overrides the
     # first). CONFIG_MODVERSIONS=y on this kernel, so modpost needs
     # Module.symvers for imported-symbol CRCs. WSL ships no symvers for
     # its kernel (a full vmlinux build would be required to make one);
     # the running kernel tolerates the gap with a "no symbol version"
     # warning. What we CAN and do version correctly is the sibling
     # module boundary: vhost_vsock imports virtio_transport_* exported
     # by vmw_vsock_virtio_transport_common, so build net/vmw_vsock first
     # and pass its Module.symvers through KBUILD_EXTRA_SYMBOLS.
     make -j"$(nproc)" M=net/vmw_vsock modules && \
     make -j"$(nproc)" M=drivers/vhost \
         KBUILD_EXTRA_SYMBOLS="$src/net/vmw_vsock/Module.symvers" modules)
    mkdir -p /usr/local/lib/kata-wsl
    cp "$src/drivers/vhost/vhost_vsock.ko" \
       "$src/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko" \
       /usr/local/lib/kata-wsl/
    cat > /etc/systemd/system/kata-vsock.service <<EOF
[Unit]
Description=Load vhost_vsock module for Kata Containers on WSL2
DefaultDependencies=no
After=systemd-modules-load.service
Before=docker.service
ConditionPathExists=/dev/kvm

[Service]
Type=oneshot
ExecStart=/usr/sbin/insmod /usr/local/lib/kata-wsl/vmw_vsock_virtio_transport_common.ko
ExecStart=/usr/sbin/insmod /usr/local/lib/kata-wsl/vhost_vsock.ko
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF
    systemctl daemon-reload
    systemctl enable --now kata-vsock.service
    [ -e /dev/vhost-vsock ]
}

# ─── 4. Optional: local registry for real manifest digests ────────────
registry_setup() {
    docker run -d --restart=always -p 5000:5000 --name kata-val-registry registry:2 || true
}

verify_kata() {
    docker info --format 'runtimes: {{json .Runtimes}}' | grep -o '"kata"'
    ls -l /dev/kvm /dev/vhost-vsock
    docker run --rm --runtime kata ubuntu:24.04 uname -r   # guest kernel
}

case "$step" in
    docker) docker_setup; docker info ;;
    kata) kata_setup ;;
    vsock) vsock_setup; ls -l /dev/vhost-vsock ;;
    registry) registry_setup; docker ps --filter name=kata-val-registry ;;
    all) docker_setup; kata_setup; vsock_setup ;;
    *) echo "usage: $0 [all|docker|kata|vsock|registry]" >&2; exit 2 ;;
esac

# Full Kata smoke test only when a kata run was actually provisioned:
# the kata step alone doesn't fix vsock, and docker/vsock/registry steps
# alone can't launch a VM.
if [ "$step" = all ] || { [ "$step" = kata ] && [ -e /dev/vhost-vsock ]; }; then
    echo "== verify =="
    verify_kata
fi

# ─── removal ──────────────────────────────────────────────────────────
# docker rm -f kata-val-registry; systemctl disable --now kata-vsock;
# rm /etc/systemd/system/kata-vsock.service; rm -rf /usr/local/lib/kata-wsl
# /opt/kata /etc/kata-containers; remove the "kata" entry from
# /etc/docker/daemon.json and `systemctl restart docker`.
# Only this script's own artifacts are removed — other VMs/engine config
# stay untouched.
