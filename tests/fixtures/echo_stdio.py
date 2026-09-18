"""Line-preserving stdio echo used as a mock MCP server in integration tests."""

import sys


def main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        line = stdin.readline()
        if not line:
            break
        stdout.write(line)
        stdout.flush()


if __name__ == "__main__":
    main()
