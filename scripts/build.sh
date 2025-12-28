#!/bin/bash
#
# Build script for BG3SE-macOS
# Builds universal binary (ARM64 + x86_64)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
SRC_DIR="${PROJECT_ROOT}/src"
LIB_DIR="${PROJECT_ROOT}/lib"

echo "=========================================="
echo "Building BG3SE-macOS"
echo "=========================================="

# Create build directory
mkdir -p "${BUILD_DIR}/lib"
mkdir -p "${BUILD_DIR}/obj"

# Check for Lua library
LUA_LIB="${LIB_DIR}/lua/liblua-universal.a"
if [ ! -f "$LUA_LIB" ]; then
    echo ""
    echo "Lua universal library not found. Building..."
    cd "${LIB_DIR}/lua"
    chmod +x build_universal.sh
    ./build_universal.sh
    cd "${PROJECT_ROOT}"
fi

# Check for Dobby library
DOBBY_LIB="${LIB_DIR}/Dobby/libdobby-universal.a"
if [ ! -f "$DOBBY_LIB" ]; then
    echo ""
    echo "Dobby universal library not found. Building..."

    # Build ARM64
    echo "  Building Dobby for ARM64..."
    cd "${LIB_DIR}/Dobby"
    mkdir -p build-arm64
    cd build-arm64
    cmake .. -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make -j8 > /dev/null 2>&1

    # Build x86_64
    echo "  Building Dobby for x86_64..."
    cd "${LIB_DIR}/Dobby"
    mkdir -p build-x86_64
    cd build-x86_64
    cmake .. -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make -j8 > /dev/null 2>&1

    # Create universal library
    echo "  Creating universal library..."
    cd "${LIB_DIR}/Dobby"
    lipo -create build-arm64/libdobby.a build-x86_64/libdobby.a -output libdobby-universal.a

    echo "  Dobby built successfully!"
    cd "${PROJECT_ROOT}"
fi

# Source files - all .c and .m files from src subdirectories
SOURCES=(
    "${SRC_DIR}/injector/main.c"
    "${SRC_DIR}/core/logging.c"
    "${SRC_DIR}/core/safe_memory.c"
    "${SRC_DIR}/console/console.c"
    "${SRC_DIR}/entity/arm64_call.c"
    "${SRC_DIR}/entity/component_lookup.c"
    "${SRC_DIR}/entity/component_property.c"
    "${SRC_DIR}/entity/component_registry.c"
    "${SRC_DIR}/entity/component_typeid.c"
    "${SRC_DIR}/entity/entity_system.c"
    "${SRC_DIR}/entity/generated_component_registry.c"
    "${SRC_DIR}/entity/guid_lookup.c"
    "${SRC_DIR}/enum/bitfield_lua.c"
    "${SRC_DIR}/enum/enum_definitions.c"
    "${SRC_DIR}/enum/enum_ext.c"
    "${SRC_DIR}/enum/enum_lua.c"
    "${SRC_DIR}/enum/enum_registry.c"
    "${SRC_DIR}/game/game_state.c"
    "${SRC_DIR}/hooks/arm64_decode.c"
    "${SRC_DIR}/hooks/arm64_hook.c"
    "${SRC_DIR}/hooks/osiris_hooks.c"
    "${SRC_DIR}/input/lua_input.c"
    "${SRC_DIR}/input/input_hooks.m"
    "${SRC_DIR}/io/path_override.c"
    "${SRC_DIR}/lifetime/lifetime.c"
    "${SRC_DIR}/localization/localization.c"
    "${SRC_DIR}/lua/lua_context.c"
    "${SRC_DIR}/lua/lua_debug.c"
    "${SRC_DIR}/lua/lua_events.c"
    "${SRC_DIR}/lua/lua_ext.c"
    "${SRC_DIR}/lua/lua_json.c"
    "${SRC_DIR}/lua/lua_localization.c"
    "${SRC_DIR}/lua/lua_logging.c"
    "${SRC_DIR}/lua/lua_osiris.c"
    "${SRC_DIR}/lua/lua_persistentvars.c"
    "${SRC_DIR}/lua/lua_resource.c"
    "${SRC_DIR}/lua/lua_staticdata.c"
    "${SRC_DIR}/lua/lua_stats.c"
    "${SRC_DIR}/lua/lua_template.c"
    "${SRC_DIR}/lua/lua_timer.c"
    "${SRC_DIR}/math/lua_math.c"
    "${SRC_DIR}/math/math_ext.c"
    "${SRC_DIR}/mod/mod_loader.c"
    "${SRC_DIR}/osiris/custom_functions.c"
    "${SRC_DIR}/osiris/osiris_functions.c"
    "${SRC_DIR}/osiris/pattern_scan.c"
    "${SRC_DIR}/overlay/overlay.m"
    "${SRC_DIR}/pak/pak_reader.c"
    "${SRC_DIR}/resource/resource_manager.c"
    "${SRC_DIR}/staticdata/staticdata_manager.c"
    "${SRC_DIR}/stats/functor_hooks.c"
    "${SRC_DIR}/stats/prototype_managers.c"
    "${SRC_DIR}/stats/stats_manager.c"
    "${SRC_DIR}/strings/fixed_string.c"
    "${SRC_DIR}/template/template_manager.c"
    "${SRC_DIR}/timer/timer.c"
    "${SRC_DIR}/vars/user_variables.c"
)

echo ""
echo "Compiling sources for universal binary (ARM64 + x86_64)..."
echo "  Total source files: ${#SOURCES[@]}"

# Compile universal binary with Dobby, Lua, and LZ4
# Use clang (C compiler) for C files - clang++ causes strict void* cast errors
clang \
    -arch x86_64 \
    -arch arm64 \
    -dynamiclib \
    -o "${BUILD_DIR}/lib/libbg3se.dylib" \
    -I"${SRC_DIR}" \
    -I"${SRC_DIR}/console" \
    -I"${SRC_DIR}/core" \
    -I"${SRC_DIR}/entity" \
    -I"${SRC_DIR}/enum" \
    -I"${SRC_DIR}/game" \
    -I"${SRC_DIR}/hooks" \
    -I"${SRC_DIR}/input" \
    -I"${SRC_DIR}/io" \
    -I"${SRC_DIR}/lifetime" \
    -I"${SRC_DIR}/localization" \
    -I"${SRC_DIR}/lua" \
    -I"${SRC_DIR}/math" \
    -I"${SRC_DIR}/mod" \
    -I"${SRC_DIR}/osiris" \
    -I"${SRC_DIR}/overlay" \
    -I"${SRC_DIR}/pak" \
    -I"${SRC_DIR}/resource" \
    -I"${SRC_DIR}/staticdata" \
    -I"${SRC_DIR}/stats" \
    -I"${SRC_DIR}/strings" \
    -I"${SRC_DIR}/template" \
    -I"${SRC_DIR}/timer" \
    -I"${SRC_DIR}/vars" \
    -I"${LIB_DIR}" \
    -I"${LIB_DIR}/lua/src" \
    -I"${LIB_DIR}/Dobby/include" \
    -L"${LIB_DIR}/Dobby" \
    -Wall -Wextra \
    -O2 \
    -fvisibility=hidden \
    -framework Cocoa \
    -framework AppKit \
    -framework QuartzCore \
    "${SOURCES[@]}" \
    "${LIB_DIR}/lz4/lz4.c" \
    "${DOBBY_LIB}" \
    "${LUA_LIB}" \
    -lz \
    -lc++

echo ""
echo "Build successful!"
echo ""

# Show info about the built dylib
echo "=== Build Output ==="
echo "Location: ${BUILD_DIR}/lib/libbg3se.dylib"
echo ""
echo "Architecture:"
file "${BUILD_DIR}/lib/libbg3se.dylib"
echo ""
echo "Size: $(ls -lh "${BUILD_DIR}/lib/libbg3se.dylib" | awk '{print $5}')"
echo ""
echo "Dependencies:"
otool -L "${BUILD_DIR}/lib/libbg3se.dylib" | head -10
echo ""
echo "=========================================="
echo "To test: Launch BG3 via Steam with wrapper"
echo "Steam launch options: /tmp/bg3w.sh %command%"
echo "=========================================="
