# godumper

A lightweight command-line tool for scanning process memory on Linux.

## Overview

`godumper` searches for byte patterns in running processes using signature scanning. I personally used it for a while as a quick and easy alternative to live debugging with heavy GUIs.

## Features

- **Wildcard support** — use `?` or `??` for unknown bytes
- **Fast scanning** — lightning fast scanning B)
- **Clean output** — simple hex addresses of matches

## Installation

```bash
go install github.com/schuhmacherandre/godumper@latest
```

Or build from source:

```bash
git clone https://github.com/schuhmacherandre/godumper
cd godumper
go build
```

## Usage

```bash
godumper scan <pid> <pattern>
```

### Examples

```bash
# Find a specific instruction sequence
godumper scan 1234 48 8B 05 C3

# Use wildcards for unknown bytes
godumper scan 1234 48 8B ?? 24

# Multiple wildcards
godumper scan 1234 ?? ?? 8B ?? C3
```

### Output

```
Matches found at:
  0x7F3A2C001A40
  0x7F3A2C00B120
```

## Requirements

- Linux (uses `/proc` filesystem)
- Read permissions for target process memory
- Root or `CAP_SYS_PTRACE` capability may be required

## How It Works

1. Parses `/proc/[pid]/maps` to find readable memory regions
2. Scans each region in 64KB chunks
3. Matches patterns byte-by-byte, treating `?`/`??` as wildcards
4. Returns all matching addresses

## License

MIT
