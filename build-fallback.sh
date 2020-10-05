#!/usr/bin/env bash

set -e
set -o pipefail

cmake \
    -DOUTPUT_NAME="argon2-fallback" \
    -DCMAKE_TOOLCHAIN_FILE=$EMSDK/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake \
    -DCMAKE_VERBOSE_MAKEFILE=OFF \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_C_FLAGS="-O3" \
    -DCMAKE_EXE_LINKER_FLAGS="-O3 --memory-init-file 0 -s NO_FILESYSTEM=1 -s 'EXPORTED_FUNCTIONS=[\"_argon2_hash\",\"_argon2_hash_ext\",\"_argon2_verify\",\"_argon2_error_message\",\"_malloc\",\"_free\"]' -s 'EXTRA_EXPORTED_RUNTIME_METHODS=[\"UTF8ToString\",\"allocate\",\"ALLOC_NORMAL\"]' -s DEMANGLE_SUPPORT=0 -s ASSERTIONS=0 -s NO_EXIT_RUNTIME=1 -s TOTAL_MEMORY=134217728 -s ALLOW_MEMORY_GROWTH=1 -s WASM=0" \
    .
cmake --build .

shasum dist/argon2-fallback.js
