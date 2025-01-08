alias build := build-debug
alias test := test-all
alias unit := test-unit
alias func := test-func

set dotenv-filename := "just.env"
set dotenv-load

setup: configure-debug configure-test-func
  ln -s $PWD/build/debug/compile_commands.json $PWD
  ln -s $PWD/build/test-func/compile_commands.json $PWD/tests

clean:
  rm -rf $PWD/build
  rm $PWD/compile_commands.json
  rm $PWD/tests/compile_commands.json

install: build-debug
  cmake: --build $PWD/build/debug --target install

build-debug: configure-debug
  cmake --build $PWD/build/debug

build-release: configure-release
  cmake --build $PWD/build/release

build-test-unit: configure-test-unit
  cmake --build $PWD/build/test-unit

build-test-func: configure-test-func
  cmake --build $PWD/build/test-func

build-test-all: configure-test-all
  cmake --build $PWD/build/test-all

test-unit: build-test-unit
  ctest --test-dir $PWD/build/test-unit

test-func: build-test-func
  ctest --test-dir $PWD/build/test-func

test-all: build-test-all
  ctest --test-dir $PWD/build/test-all

configure-debug:
  cmake -B $PWD/build/debug -S $PWD \
    -DCMAKE_INSTALL_PREFIX="$HOME/.local/" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_BUILD_UNIT_TESTS=OFF \
    -DATSDK_BUILD_FUNCTIONAL_TESTS=OFF

configure-release:
  cmake -B $PWD/build/release -S $PWD \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_BUILD_UNIT_TESTS=OFF \
    -DATSDK_BUILD_FUNCTIONAL_TESTS=OFF

configure-test-unit:
  cmake -B $PWD/build/test-unit -S $PWD \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_BUILD_UNIT_TESTS=ON \
    -DATSDK_BUILD_FUNCTIONAL_TESTS=OFF

configure-test-func:
  cmake -B $PWD/build/test-func -S $PWD \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS="func" \
    -DATSDK_BUILD_UNIT_TESTS=OFF \
    -DATSDK_BUILD_FUNCTIONAL_TESTS=ON \
    -DATDIRECTORY_HOST="\"$ATDIRECTORY_HOST\"" \
    -DATDIRECTORY_PORT="\"$ATDIRECTORY_PORT\"" \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\"" \
    -DFIRST_ATSIGN_ATSERVER_HOST="\"$FIRST_ATSIGN_ATSERVER_HOST\"" \
    -DFIRST_ATSIGN_ATSERVER_PORT="\"$FIRST_ATSIGN_ATSERVER_PORT\"" \
    -DSECOND_ATSIGN_ATSERVER_HOST="\"$SECOND_ATSIGN_ATSERVER_HOST\"" \
    -DSECOND_ATSIGN_ATSERVER_PORT="\"$SECOND_ATSIGN_ATSERVER_PORT\""

configure-test-all:
  cmake -B $PWD/build/test-all -S $PWD \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=ON \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\""

show-env:
  echo "$FIRST_ATSIGN"
  echo "$SECOND_ATSIGN"
  echo "$C_COMPILER"
