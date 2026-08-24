# Upstream and licensing

SxSSD is a research fork of [FEMU](https://github.com/MoatLab/FEMU),
which is based on [QEMU](https://www.qemu.org/). It uses FEMU commit
`b3272c0130faa5fd04826303541a831731a8dfb2`.

SxSSD changes are Copyright (C) 2025–2026 Josh Dafoe and licensed
`GPL-2.0-or-later`. The combined emulator remains GPLv2. Third-party
components retain their own licenses; bundled pqueue is BSD-2-Clause.

The exact evaluation snapshot is commit `d4e3d55b6`. This branch adds only
licensing and packaging metadata. That snapshot dynamically links against a
separately installed OpenSSL and does not bundle OpenSSL runtime libraries.
