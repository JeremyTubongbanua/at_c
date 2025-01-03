#!/bin/bash

# ##########
# This script CMake configures and builds the project for functional tests assuming virtual environment is already setup.
# ##########

FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"

# 1. Go to the root of the project
cd ../../..

# 2. Variables

# 2.1 Default values
ATSIGN_FIRST="@alice🛠"
ATSIGN_SECOND="@bob🛠"
ATDIRECTORY_HOST="vip.ve.atsign.zone"
ATDIRECTORY_PORT=64

# 2.2 Parse command line arguments
while getopts f:s:h:p: flag
do
    case "${flag}" in
        f) ATSIGN_FIRST=${OPTARG};;
        s) ATSIGN_SECOND=${OPTARG};;
        h) ATDIRECTORY_HOST=${OPTARG};;
        p) ATDIRECTORY_PORT=${OPTARG};;
    esac
done

# 2.3 Print variables
echo "ATSIGN_FIRST (-f): $ATSIGN_FIRST"
echo "ATSIGN_SECOND (-s): $ATSIGN_SECOND"
echo "ATDIRECTORY_HOST (-h): $ATDIRECTORY_HOST"
echo "ATDIRECTORY_PORT (-p): $ATDIRECTORY_PORT"

# 3. CMake configure
cmake -S . -B build \
    -DATSDK_BUILD_TESTS="func"                  \
    -DCMAKE_BUILD_TYPE=Debug                    \
    -DFIRST_ATSIGN="\"$ATSIGN_FIRST\""          \
    -DSECOND_ATSIGN="\"$ATSIGN_SECOND\""        \
    -DATDIRECTORY_HOST="\"$ATDIRECTORY_HOST\""  \
    -DATDIRECTORY_PORT=$ATDIRECTORY_PORT

# 4. CMake build (this step will build atsdk and link the atsdk to the functional
cmake --build build 
