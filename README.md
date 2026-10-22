<!--
# SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
# SPDX-License-Identifier: GPL-3.0-or-later

# SPDX-FileCopyrightText: 2018 yuzu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later
-->
<!-- lang: en-GB -->

<h1 align="center">
  <a href="https://github.com/jun9100/eden">
    <img src="./dist/qt_themes/default/icons/256x256/eden.png" alt="Eden" width="160">
  </a>
  <br>
  Eden
</h1>

<p align="center">
  Free and open-source Nintendo Switch emulator written in C++20.
  <br>
  <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#platforms">Platforms</a> |
  <a href="#building">Building</a> |
  <a href="#documentation">Documentation</a> |
  <a href="#contributing">Contributing</a> |
  <a href="#license">License</a>
</p>

## Features

- Qt 6 desktop application, Android application, and the `eden-cli` command-line frontend.
- Vulkan renderer across supported targets; OpenGL is available on compatible desktop builds.
- Core emulation, audio, input, shader recompilation, mod management, firmware management, save data, and multiplayer-room components are maintained in separate modules.
- Optional desktop facilities include a standalone `eden-room` server, update checking, camera/web applet integration, and ReShade FX post-processing.
- CMake downloads or discovers dependencies through CPM, with options for bundled Qt, FFmpeg, SDL3, MoltenVK, and OpenSSL where applicable.

## Platforms

The primary development and test targets are Windows, Linux, macOS, and Android. The project also contains platform support for FreeBSD, OpenBSD, NetBSD, Haiku, and OpenIndiana/Solaris.

| Target | Architectures | Notes |
| --- | --- | --- |
| Windows 10/11 | x86_64; ARM64 experimental | Desktop Qt frontend and CLI |
| Linux | x86_64; ARM64 experimental; riscv64 limited | Desktop Qt frontend and CLI |
| macOS | Apple silicon; Intel builds are less tested | Uses MoltenVK for Vulkan |
| Android | ARM64 | Native Android frontend |
| Other Unix-like systems | Varies by platform | See the platform notes before building |

For caveats, GPU guidance, and the precise support status of each architecture, see [Platforms and Architectures](docs/user/Architectures.md).

## Building

Eden uses CMake 3.31 or newer and C++20. Desktop builds require the dependencies for the selected platform; the complete requirements are in the [dependency guide](docs/Deps.md).

```sh
git clone https://github.com/jun9100/eden.git
cd eden

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DYUZU_TESTS=OFF
cmake --build build
```

The desktop executable is written to `build/bin/eden` (`eden.exe` on Windows, or `eden.app` on macOS). To build only the command-line frontend on a non-Android target, disable the Qt frontend:

```sh
cmake -S . -B build-cli -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_QT=OFF
cmake --build build-cli
```

This produces `eden-cli` in `build-cli/bin`. Android is built through the Gradle project in `src/android`; follow the [Android build guide](docs/build/Android.md).

The [general build guide](docs/Build.md) covers Qt Creator, Visual Studio, CLion, build options, troubleshooting, and platform-specific details.

## Documentation

- [User Handbook](docs/user/README.md): setup, settings, controllers, graphics, mods, saves, updates/DLC, and multiplayer.
- [Quickstart](docs/user/QuickStart.md): first-run guidance for Windows, Steam Deck, and macOS.
- [Command-line reference](docs/user/CommandLine.md): using `eden-cli`.
- [Developer tools](tools/README.md): translation, shader, and supporting development tooling.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or submitting a patch. It covers contribution routes, code policy, translations, and the expected build verification.

## License

Eden is licensed under the [GNU General Public License, version 3 or later](LICENSE.txt).

## Acknowledgements

Eden builds on the work of the yuzu project and incorporates contributions from the wider emulator and open-source communities.
