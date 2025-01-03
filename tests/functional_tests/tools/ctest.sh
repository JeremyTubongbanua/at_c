#!/bin/bash
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"

# 1. Go to root of the project

cd ../../..

# 2. Check if build directory exists

if [ ! -d "build" ]; then
    echo "Build directory does not exist. Run build.sh first."
    exit 1
fi

# 3. Run ctest

ctest --test-dir build/tests/functional_tests --output-on-failure -VV --timeout 90

