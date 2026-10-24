#!/bin/sh
# Fetch the pinned real MCP servers used by tests/real_servers_e2e.rs.
# No arguments. Idempotent: skips each runtime that is already installed.
set -eu
cd "$(dirname "$0")"

# Node: package-lock.json is committed; npm ci reproduces it exactly.
# node_modules counts as installed only when the marker written after a
# successful npm ci is present — a partial tree from an interrupted run is
# rebuilt (npm ci clears node_modules itself), not mistaken for installed.
if [ -f node/node_modules/.install-complete ]; then
    echo "setup: node already installed (node/node_modules present)"
else
    (cd node && npm ci --ignore-scripts)
    touch node/node_modules/.install-complete
    echo "setup: node installed"
fi

# Python: requirements.txt pins every artifact by sha256. A venv counts as
# installed only when the marker written after a successful pip install is
# present — a leftover from an interrupted run is removed and recreated.
#
# Debian/Ubuntu split venv's pip bootstrap into the `python3-venv`
# package — `python3 -m venv` fails there on missing ensurepip. The
# fallback builds the venv --without-pip and runs the pip wheel named by
# requirements.txt itself, verified against the same sha256 the install
# step enforces — the bootstrap is as pinned as the payload.
if [ -f python/.venv/.install-complete ]; then
    echo "setup: python already installed (python/.venv present)"
else
    rm -rf python/.venv
    if python3 -m venv python/.venv; then
        python/.venv/bin/python -m pip install --require-hashes -r python/requirements.txt
    else
        rm -rf python/.venv
        bootstrap=$(python3 - <<'PY'
import hashlib, json, os, re, sys, tempfile, urllib.request

lines = open("python/requirements.txt").read().splitlines()
version = None
hashes = []
for i, line in enumerate(lines):
    m = re.match(r"pip==([0-9A-Za-z.]+)\s*\\?$", line.strip())
    if m:
        version = m.group(1)
        j = i + 1
        while j < len(lines) and "--hash=sha256:" in lines[j]:
            h = re.search(r"--hash=sha256:([0-9a-f]{64})", lines[j])
            hashes.append(h.group(1))
            j += 1
        break
if not version or not hashes:
    sys.exit("setup: pinned pip entry not found in python/requirements.txt")
meta = json.load(
    urllib.request.urlopen(f"https://pypi.org/pypi/pip/{version}/json")
)
wheel = next(
    (u for u in meta["urls"] if u["packagetype"] == "bdist_wheel"), None
)
if wheel is None:
    sys.exit(f"setup: no bdist_wheel published for pip {version}")
# Keep the canonical wheel filename — pip refuses an artifact whose
# name does not parse as {dist}-{version}-{tags}.
out = os.path.join(
    tempfile.mkdtemp(), f"pip-{version}-py3-none-any.whl"
)
urllib.request.urlretrieve(wheel["url"], out)
# The downloaded artifact is what gets trusted — hash the bytes, not
# the index metadata that named them.
digest = hashlib.sha256(open(out, "rb").read()).hexdigest()
if digest not in hashes:
    sys.exit(f"setup: downloaded pip {version} wheel matches no requirements.txt hash")
print(out)
PY
)
        wheel=$bootstrap
        python3 -m venv --without-pip python/.venv
        # A wheel is a zip — `python -m pip` inside it is the standard
        # bootstrap (the same thing pip.pyz wraps). --require-hashes
        # applies to the payload install exactly as on the primary path.
        PYTHONPATH="$wheel" python/.venv/bin/python -m pip \
            install --require-hashes -r python/requirements.txt
        # The bootstrap zip satisfies `pip` on sys.path, so the
        # requirements pass leaves the venv without its own pip —
        # install the verified wheel in; it is exactly the artifact
        # requirements.txt pins.
        PYTHONPATH="$wheel" python/.venv/bin/python -m pip \
            install --no-deps --ignore-installed "$wheel"
    fi
    touch python/.venv/.install-complete
    echo "setup: python installed"
fi

echo "setup: done"
