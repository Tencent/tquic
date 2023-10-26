---
title: Installation
sidebar_position: 1
---

# Installation

## Failed to run custom build command for TQUIC?

If you get a `not found CMakeLists.txt` error, it is likely because the submodules of tquic were not downloaded properly.

```
error: failed to run custom build command for `tquic`

...
  CMake Error: The source directory "third_party/boringssl" does not appear to contain CMakeLists.txt.
  Specify --help for usage, or press the help button on the CMake GUI.
  thread 'main' panicked at '
  command did not execute successfully, got: exit status: 1

  build script failed, must exit now', index.crates.io/cmake-0.1.50/src/lib.rs:1098:5
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

The source code of tquic should be cloned using the `--recursive` option:
```
git clone https://github.com/tencent/tquic --recursive
```

If the source code has already been cloned, but you forgot to use the option `--recursive`, you can manually download the submodules like this:
```
git submodule init && git submodule update
```


## Not found example tools of TQUIC?

If you cannot locate the example tools in the directory `./target/release`, it is likely because you forgot to include the build option `--all` or `--release`.


## Not found C library of TQUIC?

If you cannot locate the static or dynamic c library of tquic in the directory `./target/release`, it is likely because you forgot to include the build option `-F ffi` or `--release`.

