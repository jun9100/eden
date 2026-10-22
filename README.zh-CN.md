<!--
# SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
# SPDX-License-Identifier: GPL-3.0-or-later

# SPDX-FileCopyrightText: 2018 yuzu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later
-->
<!-- lang: zh-CN -->

<h1 align="center">
  <a href="https://github.com/jun9100/eden">
    <img src="./dist/qt_themes/default/icons/256x256/eden.png" alt="Eden" width="160">
  </a>
  <br>
  Eden
</h1>

<p align="center">
  使用 C++20 编写的自由、开源 Nintendo Switch 模拟器。
  <br>
  <a href="README.md">English</a>
</p>

<p align="center">
  <a href="#功能">功能</a> |
  <a href="#平台">平台</a> |
  <a href="#构建">构建</a> |
  <a href="#文档">文档</a> |
  <a href="#参与贡献">参与贡献</a> |
  <a href="#许可证">许可证</a>
</p>

## 功能

- 提供基于 Qt 6 的桌面应用、Android 应用和 `eden-cli` 命令行前端。
- 在受支持的平台上使用 Vulkan 渲染器；兼容的桌面构建可启用 OpenGL。
- 核心模拟、音频、输入、着色器重编译、Mod 管理、固件管理、存档和多人房间分别由独立模块维护。
- 桌面端可选构建独立 `eden-room` 服务器、更新检查、相机与 Web Applet 集成，以及 ReShade FX 后处理。
- CMake 通过 CPM 下载或查找依赖；在适用的平台上可选择捆绑 Qt、FFmpeg、SDL3、MoltenVK 和 OpenSSL。

## 平台

Windows、Linux、macOS 和 Android 是主要开发与测试目标。项目还包含对 FreeBSD、OpenBSD、NetBSD、Haiku 和 OpenIndiana/Solaris 的平台支持。

| 目标平台 | 架构 | 说明 |
| --- | --- | --- |
| Windows 10/11 | x86_64；ARM64 为实验性支持 | Qt 桌面前端和 CLI |
| Linux | x86_64；ARM64 为实验性支持；riscv64 支持有限 | Qt 桌面前端和 CLI |
| macOS | Apple Silicon；Intel 构建测试较少 | 通过 MoltenVK 使用 Vulkan |
| Android | ARM64 | 原生 Android 前端 |
| 其他类 Unix 系统 | 因平台而异 | 构建前请阅读平台说明 |

各架构的限制、GPU 建议和准确的支持状态，请参阅[平台和架构说明](docs/user/Architectures.md)。

## 构建

Eden 使用 CMake 3.31 或更高版本及 C++20。桌面端构建需要安装目标平台的依赖，完整要求请见[依赖指南](docs/Deps.md)。

```sh
git clone https://github.com/jun9100/eden.git
cd eden

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DYUZU_TESTS=OFF
cmake --build build
```

桌面可执行文件位于 `build/bin/eden`；Windows 为 `eden.exe`，macOS 为 `eden.app`。若要仅在非 Android 平台构建命令行前端，请禁用 Qt 前端：

```sh
cmake -S . -B build-cli -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_QT=OFF
cmake --build build-cli
```

该命令会在 `build-cli/bin` 生成 `eden-cli`。Android 通过 `src/android` 中的 Gradle 项目构建，请参阅 [Android 构建指南](docs/build/Android.md)。

[通用构建指南](docs/Build.md)还包含 Qt Creator、Visual Studio、CLion、构建选项、故障排查及平台专属说明。

## 文档

- [用户手册](docs/user/README.md)：设置、控制器、图形、Mod、存档、更新/DLC 和多人游戏。
- [快速开始](docs/user/QuickStart.md)：Windows、Steam Deck 和 macOS 的首次运行说明。
- [命令行参考](docs/user/CommandLine.md)：`eden-cli` 的使用方法。
- [开发工具](tools/README.md)：翻译、着色器及其他开发辅助工具。

## 参与贡献

提交 Issue 或补丁前，请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。其中说明了贡献渠道、代码政策、翻译工作和预期的构建验证。

## 许可证

Eden 采用 [GNU 通用公共许可证 v3 或更高版本](LICENSE.txt)发布。

## 致谢

Eden 建立在 yuzu 项目的工作之上，也吸收了更广泛的模拟器及开源社区的贡献。
