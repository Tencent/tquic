---
title: Installation
sidebar_position: 1
---

# Installation

## Supported Platforms

TQUIC is written in the [Rust language](https://www.rust-lang.org/). Currently, it runs on Linux, MacOS, iOS, and Android, with future versions planned for other platforms.


## Prerequisites

* [rust 1.70+](https://www.rust-lang.org/tools/install)
* [git 2.0+](https://git-scm.com/downloads)
* [gcc 9.3+](https://gcc.gnu.org/releases.html)
* [cmake 3.22+](https://cmake.org/download/)


## Building

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="Linux" label="Linux" default>

To build TQUIC for Linux, run the following commands:
```bash
git clone https://github.com/tencent/tquic --recursive
cd tquic

cargo build --release --all
```

:::tip
The `--release` option enables cargo to build optimized artifacts and put them in the directory `./target/release/`, instead of the default location `./target/debug/`.

The `--all` option enables cargo to build both the tquic library and example tools.
:::

If you want to enable the C API, just add `-F ffi` option to the `cargo build` command:

```bash
cargo build --release -F ffi
```
  </TabItem>


  <TabItem value="MacOS" label="MacOS">

To build TQUIC for MacOS, run the following commands:
```bash
git clone https://github.com/tencent/tquic --recursive
cd tquic

cargo build --release --all
```

:::tip
The `--release` option enables cargo to build optimized artifacts and put them in the directory `./target/release/`, instead of the default location `./target/debug/`.

The `--all` option enables cargo to build both the tquic library and example tools.
:::

If you want to enable the C API, just add `-F ffi` option to the `cargo build` command:

```bash
cargo build --release -F ffi
```
  </TabItem>


  <TabItem value="Android" label="Android">

To build TQUIC for Android, you need the following:

* [Install Android NDK](https://developer.android.com/studio/projects/install-ndk?hl=zh-cn) and set the `ANDROID_NDK_HOME` environment variable

```bash
# Set the ANDROID_NDK_HOME environment variable to the NDK installation path 
export ANDROID_NDK_HOME=/path/to/android-ndk
```

* Install Rust toolchain for Android and cargo-ndk

```bash
# Install Rust toolchain for Android
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Install cargo-ndk for building libraries for Android without hassle
cargo install cargo-ndk
```

To build the TQUIC library, run the following commands:

```bash
git clone https://github.com/tencent/tquic --recursive
cd tquic

# The -t <architecture> and -p <NDK version> options are mandatory.
cargo ndk -t arm64-v8a -p 21 -- build --features ffi --release
```
  </TabItem>


  <TabItem value="iOS" label="iOS">

To build TQUIC for iOS, you need the following:

* [Install Xcode](https://developer.apple.com/xcode/) and Xcode command-line tools

```bash
# Install Xcode command-line tools. 
xcode-select --install
```
  
* Install Rust toolchain for iOS and cargo-lipo
```bash
# Install the Rust toolchain for iOS
rustup target add aarch64-apple-ios x86_64-apple-ios
  
# Install cargo-lipo for automatically creating universal libraries for iOS 
cargo install cargo-lipo
```

To build the TQUIC library, run the following commands:
```bash
git clone https://github.com/tencent/tquic --recursive
cd tquic

cargo lipo --features ffi --release
```
  </TabItem>

</Tabs>


## Running the tests

The command below runs unit tests:

```bash
cargo test
```


## Further readings

* [How to use the demo client and demo server](./demo)
* [How to use the API of TQUIC](../category/tutorial)


## Problems?

* Please refer to the [documentation for common installation issues](../faq/installation) first.
* Ask for help on our [GitHub issues](https://github.com/tencent/tquic/issues).
