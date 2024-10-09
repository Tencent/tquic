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
        "aarch64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
            ("CMAKE_ASM_FLAGS", "-fembed-bitcode -target arm64-apple-ios"),
        ],
    ),
    (
        "aarch64-apple-ios-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            (
                "CMAKE_ASM_FLAGS",
                "-fembed-bitcode -target arm64-apple-ios-simulator",
            ),
            ("CMAKE_THREAD_LIBS_INIT", "-lpthread"),
            ("CMAKE_HAVE_THREADS_LIBRARY", "1"),
            ("THREADS_PREFER_PTHREAD_FLAG", "ON"),
        ],
    ),
    (
        "x86_64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            (
                "CMAKE_ASM_FLAGS",
                "-fembed-bitcode -target x86_64-apple-ios-simulator",
            ),
        ],
    ),
];

/// Additional parameters for Ohos
const CMAKE_PARAMS_OHOS_NDK: &[(&str, &[(&str, &str)])] =
    &[("aarch64", &[("OHOS_ARCH", "arm64-v8a")])];

/// Create a cmake::Config for building BoringSSL.
fn new_boringssl_cmake_config() -> cmake::Config {
    let target = std::env::var("TARGET").unwrap();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut boringssl_cmake = cmake::Config::new("deps/boringssl");

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
            for (ios_target, params) in CMAKE_PARAMS_IOS {
                if *ios_target == target {
                    for (name, value) in *params {
                        boringssl_cmake.define(name, value);
                        if *name == "CMAKE_ASM_FLAGS" {
                            boringssl_cmake.cflag(value);
                        }
                    }
                    break;
                }
            }
        }

        "linux" => {
            if target.ends_with("ohos") {
                for (ohos_arch, params) in CMAKE_PARAMS_OHOS_NDK {
                    if *ohos_arch == arch {
                        for (name, value) in *params {
                            boringssl_cmake.define(name, value);
                        }
                        break;
                    }
                }

                let ohos_ndk_home = std::env::var("OHOS_NDK_HOME")
                    .expect("Please set OHOS_NDK_HOME for Harmony build");
                let ohos_ndk_home = std::path::Path::new(&ohos_ndk_home);
                let toolchain_file = ohos_ndk_home.join("native/build/cmake/ohos.toolchain.cmake");
                let toolchain_file = toolchain_file.to_str().unwrap();
                boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);
            }
        }

        _ => (),
    };

    boringssl_cmake
}

/// Return the build sub-dir for boringssl.
fn get_boringssl_build_sub_dir() -> &'static str {
    if !cfg!(target_env = "msvc") {
        return "";
    }

    // Note: MSVC outputs static libs in a sub-directory.
    let debug = std::env::var("DEBUG").expect("DEBUG not set");
    let opt_level = std::env::var("OPT_LEVEL").expect("OPT_LEVEL not set");

    match &opt_level[..] {
        "1" | "2" | "3" => {
            if &debug[..] == "true" {
                "RelWithDebInfo"
            } else {
                "Release"
            }
        }
        "s" | "z" => "MinSizeRel",
        _ => "Debug",
    }
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
        let sub_dir = get_boringssl_build_sub_dir();
        let build_dir = format!("{boringssl_dir}/build/{sub_dir}");
        println!("cargo:rustc-link-search=native={build_dir}");
    }

    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
}
