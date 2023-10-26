// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Additional parameters for Android
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

/// Additional parameters for iOS
const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
        ],
    ),
    (
        "x86_64",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
];

/// Create a cmake::Config for building BoringSSL.
fn new_boringssl_cmake_config() -> cmake::Config {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut boringssl_cmake = cmake::Config::new("src/third_party/boringssl");

    match os.as_ref() {
        "android" => {
            for (android_arch, params) in CMAKE_PARAMS_ANDROID_NDK {
                if *android_arch == arch {
                    for (name, value) in *params {
                        boringssl_cmake.define(name, value);
                    }
                    break;
                }
            }

            let android_ndk_home = std::env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            let android_ndk_home = std::path::Path::new(&android_ndk_home);
            let toolchain_file = android_ndk_home.join("build/cmake/android.toolchain.cmake");
            let toolchain_file = toolchain_file.to_str().unwrap();
            boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

            boringssl_cmake.define("ANDROID_NATIVE_API_LEVEL", "21");
            boringssl_cmake.define("ANDROID_STL", "c++_shared");
        }

        "ios" => {
            for (ios_arch, params) in CMAKE_PARAMS_IOS {
                if *ios_arch == arch {
                    for (name, value) in *params {
                        boringssl_cmake.define(name, value);
                    }
                    break;
                }
            }

            let mut cflag = "-fembed-bitcode".to_string();
            if arch == "x86_64" {
                cflag.push_str(" -target x86_64-apple-ios-simulator");
            }
            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);
        }

        _ => (),
    };

    boringssl_cmake
}

fn main() {
    if let Ok(boringssl_lib_dir) = std::env::var("BORINGSSL_LIB_DIR") {
        // Build with static boringssl lib.
        // Boringssl lib should turn on CMAKE_POSITION_INDEPENDENT_CODE
        // option when compile to build dynamic tquic lib.
        println!("cargo:rustc-link-search=native={boringssl_lib_dir}");
    } else {
        // Build with boringssl code.
        let boringssl_dir = {
            let mut cfg = new_boringssl_cmake_config();

            cfg.build_target("ssl").build();
            cfg.build_target("crypto").build().display().to_string()
        };
        let build_dir = format!("{boringssl_dir}/build/");
        println!("cargo:rustc-link-search=native={build_dir}");
    }

    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
}
