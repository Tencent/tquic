---
title: Development Guides
sidebar_position: 3
---

# Development guides


## Layout of the top level directories

The top directories are as followings:

| Directory | Description |
| --------- | ----------- |
| src/       | TQUIC implementation |
| tools/      | TQUIC Example tools |
| benches/   | Benchmark tests |
| fuzz/      | Fuzzing tests |
| interop/   | Interoperability testing |
| include/   | Generated header files for C/C++ |
| website/   | TQUIC website for documents |

:::tip
The header file `include/tquic.h` should be updated if any changes are made to the `src/ffi.rs`.
The header file can be automatically generated using the following command:
```
cbindgen -o include/tquic.h
```
:::


## Layout of the TQUIC implementation

| Directory/File | Description |
| -------------- | ----------- |
| src/connection/           | Core implementation of the QUIC protocol |
| src/congestion_control/   | Various congestion control algorithms |
| src/multipath_scheduler/  | Various multipath scheduling algorithms |
| src/tls/                  | An wrapper of boringssl/rustls |
| src/h3/                   | HTTP/3 protocol |
| src/qlog/                 | Qlog |
| src/ffi.rs                | Foreign Function Interface for C/C++ |
| src/build.rs              | Build tools for boringssl |
| src/\*.rs                 | Fundamental building blocks for the TQUIC library |


## Unit testing

* How to output test case logs

```
# You should replace the `test_name` with the actual test case name
RUST_LOG=trace cargo test test_name -- --nocapture
```

* How to check the unit test coverage

It is recommended to use `tarpaulin` to produce a unit test coverage report:

```
# install tarpaulin
cargo install cargo-tarpaulin

# change to the base directory of the project
cargo tarpaulin --exclude-files "deps/*" -o html
```


## Fuzz testing

* How to install the tool [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) for for fuzzing
```
rustup install nightly
rustup default nightly
cargo install cargo-fuzz
```

* How to list all the existing fuzz targets
```
cargo fuzz list
```

* How to run a fuzzing target
```
cargo fuzz run <target_name> -- -max_total_time=30
```

Refer to the [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html) for more information.


## Conformance testing

We maintaine a formal specification of the [QUIC v1](https://datatracker.ietf.org/doc/html/rfc9000) protocol using the [Ivy language](http://microsoft.github.io/ivy/). This specification can be used to test implementations of QUIC using [compositional specification-based testing methods](https://dl.acm.org/doi/10.1145/3341302.3342087).

For further information, kindly consult [this document](../further_readings/conformance).


## Interoperability testing

Automated, continuous interop testing is performed using the [quic-interop-runner](https://github.com/marten-seemann/quic-interop-runner/tree/master). The results of this continuous testing are posted on [this webpage](https://interop.seemann.io/).


## Rust package documentation

* How to build the documentation for [tquic](https://docs.rs/tquic)

```
cargo doc --no-deps
```
