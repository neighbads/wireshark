# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

Wireshark uses CMake with Ninja as the preferred generator:

```bash
# Configure and build
mkdir build && cd build
cmake -GNinja ..
ninja

# Build specific targets
ninja wireshark          # Qt GUI application
ninja tshark             # CLI packet analyzer
ninja dumpcap            # Packet capture utility

# Build test programs (required before running tests)
ninja test-programs
```

Key CMake options: `-DBUILD_wireshark=ON`, `-DUSE_qt6=ON` (default), `-DENABLE_WERROR=ON` (default). See `CMakeOptions.txt` for all options.

Requirements: CMake 3.20+, C11, C++14, Python 3.6+, Qt 5.15+/Qt 6 (for GUI), GLib 2.54.0+, libpcap, Flex.

## Testing

Tests use pytest (Python):

```bash
# Install test dependencies
pip install pytest pytest-xdist

# Run all tests (from build directory)
pytest

# Run a specific test suite
pytest test/suite_decryption.py

# Run a specific test
pytest test/suite_decryption.py::TestDecrypt80211 -k "test_name"

# Run tests in parallel
pytest -n auto
```

Test captures are in `test/captures/`, baseline files in `test/baseline/`.

## Architecture

Wireshark is primarily C, with the Qt GUI in C++.

### Core Libraries

- **epan/** — Packet analysis engine (libwireshark). Contains the dissection framework, display filter engine (`dfilter/`), and protocol dissectors (`dissectors/` — ~1,700 files)
- **wiretap/** — Capture file I/O library (libwiretap). Reads/writes pcap, pcapng, and dozens of other formats
- **wsutil/** — Utility library (libwsutil). Platform abstractions, file utilities (`file_util.h`), and common helpers
- **capture/** — Capture engine internals (uses dumpcap as a privileged helper)
- **wmem/** — Wireshark memory allocator (in `epan/wmem/`). Provides scoped, leak-free memory management for dissectors

### Applications

- **ui/qt/** — Wireshark Qt GUI (C++)
- **ui/** — Shared UI code
- **tshark** — CLI analyzer (main in `tshark.c`)
- **sharkd** — Daemon mode for remote/API access

### Extension Points

- **plugins/** — Loadable plugin dissectors and codecs
- **epan/wslua/** — Lua scripting bindings for custom dissectors
- **extcap/** — External capture interface programs (sshdump, androiddump, etc.)

### Key Skeleton/Templates

- `doc/packet-PROTOABBREV.c` — Template for new dissectors
- `doc/README.dissector` — Comprehensive guide for writing dissectors
- `doc/README.developer` — General development practices
- `doc/README.wmem` — Memory management guide
- `doc/README.heuristic` — Heuristic dissector guide
- `doc/README.tapping` — Tap interface guide

## Coding Conventions

### C/C++ Style
- 4-space indentation for C/C++ (tabs for CMake and Flex files)
- Use C11 fixed-width types: `uint8_t`, `uint16_t`, `uint32_t`, `int64_t` (not `guint8`, `gchar`, etc.)
- Use `<inttypes.h>` macros for printing: `PRIu64`, `PRId64` (not `%lld`)
- Use `bool` from `<stdbool.h>` for booleans
- Include `<wireshark.h>` rather than individual standard headers
- Avoid GLib type synonyms (`gchar`, `gint`, `gpointer`) — use standard C types

### File I/O
- Use `ws_open()`, `ws_fopen()`, `ws_rename()`, `ws_stat()`, `ws_unlink()`, etc. instead of direct POSIX calls (from `<wsutil/file_util.h>`) for UTF-8 path support on Windows

### Byte Order
- Use `tvb_get_letohs()`/`tvb_get_letohl()` for little-endian values — never fetch with `tvb_get_ntohs()` then swap with `g_ntohs()`

### Memory Management
- Use wmem allocators for dissector memory — provides automatic scoped cleanup
- Dissector memory typically uses `wmem_file_scope()` or `pinfo->pool` (packet scope)

## Commit Messages

Use the repository template: `git config commit.template .gitmessage`

Format: `<component>[: <subcomponent>]: <imperative summary>`

Examples:
- `SMPP: Fix request/response tracking (#20891)`
- `CMake: Allow users to override _FORTIFY_SOURCE`

AI usage must be declared: `AI-Assisted: yes (Claude)` or `AI-Assisted: no`

## Git Hooks

Enable shipped hooks: `git config core.hooksPath tools/git_hooks`
