cmake_minimum_required(VERSION 3.22.1)
project(meshcore_jsi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(MESH_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(RUST_DIR  "${MESH_ROOT}/rust")

# The JSI layer is byte-identical to the one the iOS pod compiles. Sharing the
# source, not just the design, is what keeps the two platforms from drifting.
add_library(meshcore_jsi SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/OnLoad.cpp"
    "${MESH_ROOT}/shared/cpp/MeshCoreHostObject.cpp"
)

target_include_directories(meshcore_jsi PRIVATE
    "${MESH_ROOT}/shared/cpp"
    "${RUST_DIR}/meshcore-ffi/include"   # cbindgen output: meshcore.h
)

# ---------------------------------------------------------------------------
# The Rust core, prebuilt by cargo-ndk into src/main/jniLibs/<abi>/
# ---------------------------------------------------------------------------
add_library(meshcore_ffi SHARED IMPORTED)
set_target_properties(meshcore_ffi PROPERTIES
    IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libmeshcore_ffi.so"
)

# ---------------------------------------------------------------------------
# React Native
# ---------------------------------------------------------------------------
find_package(ReactAndroid REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)

# RN consolidated most prefab targets into ReactAndroid::reactnative in 0.76.
# Support both layouts so this file is not pinned to one RN minor.
if(TARGET ReactAndroid::reactnative)
    set(RN_LIBS ReactAndroid::reactnative ReactAndroid::jsi)
else()
    set(RN_LIBS
        ReactAndroid::react_nativemodule_core
        ReactAndroid::turbomodulejsijni
        ReactAndroid::jsi
    )
endif()

target_link_libraries(meshcore_jsi
    meshcore_ffi
    ${RN_LIBS}
    fbjni::fbjni
    android
    log
)

# -Wl,--no-undefined turns "missing mesh_* symbol" from a runtime dlopen crash
# on a user's phone into a link error on your machine.
target_link_options(meshcore_jsi PRIVATE "-Wl,--no-undefined")
