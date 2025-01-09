alias build := build-debug
alias test := test-all
alias unit := test-unit
alias func := test-func
alias memd := memcheck-docker

set dotenv-filename := "just.env"
set dotenv-load

# SETUP COMMANDS

setup: configure-debug configure-test-func
  ln -s $PWD/build/debug/compile_commands.json $PWD
  ln -s $PWD/build/test-func/compile_commands.json $PWD/tests

setup-memcheck-docker:
  docker build --platform linux/amd64 -t atc-memcheck-docker:latest -f $PWD/valgrind.Dockerfile $PWD

clean:
  rm -rf $PWD/build
  rm $PWD/compile_commands.json
  rm $PWD/tests/compile_commands.json

# INSTALL COMMANDS

install: build-debug
  cmake: --build $PWD/build/debug --target install

# BUILD COMMANDS

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

build-test-memcheck: configure-test-memcheck
  cmake --build $PWD/build/test-memcheck

# TEST COMMANDS

test-unit +ARGS='': build-test-unit
  ctest --test-dir $PWD/build/test-unit {{ARGS}}

test-func +ARGS='': build-test-func
  ctest --test-dir $PWD/build/test-func {{ARGS}}

test-all +ARGS='': build-test-all
  ctest --test-dir $PWD/build/test-all {{ARGS}}

memcheck +ARGS='': build-test-memcheck
  ctest -T memcheck --test-dir $PWD/build/test-memcheck {{ARGS}}

memcheck-docker +ARGS='':
  docker run --rm --platform linux/amd64 --mount type=bind,src=$PWD,dst=/mnt/at_c atc-memcheck-docker:latest \
    just memcheck {{ARGS}}

# CONFIGURE COMMANDS

configure-debug:
  cmake -B $PWD/build/debug -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_INSTALL_PREFIX="$HOME/.local/" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_MEMCHECK=OFF

configure-release:
  cmake -B $PWD/build/release -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_MEMCHECK=OFF

configure-test-unit:
  cmake -B $PWD/build/test-unit -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error " \
    -DATSDK_BUILD_TESTS="unit" \
    -DATSDK_MEMCHECK=OFF

configure-test-func:
  cmake -B $PWD/build/test-func -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS="func" \
    -DATSDK_MEMCHECK=OFF \
    -DATDIRECTORY_HOST="\"$ATDIRECTORY_HOST\"" \
    -DATDIRECTORY_PORT=$ATDIRECTORY_PORT \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\"" \
    -DFIRST_ATSIGN_ATSERVER_HOST="\"$FIRST_ATSIGN_ATSERVER_HOST\"" \
    -DFIRST_ATSIGN_ATSERVER_PORT=$FIRST_ATSIGN_ATSERVER_PORT \
    -DSECOND_ATSIGN_ATSERVER_HOST="\"$SECOND_ATSIGN_ATSERVER_HOST\"" \
    -DSECOND_ATSIGN_ATSERVER_PORT=$SECOND_ATSIGN_ATSERVER_PORT

configure-test-all:
  cmake -B $PWD/build/test-all -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error " \
    -DATSDK_BUILD_TESTS=ON \
    -DATSDK_MEMCHECK=OFF \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\""

configure-test-memcheck:
  cmake -B $PWD/build/test-memcheck -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=gnu99 -Wno-error" \
    -DATSDK_BUILD_TESTS=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DATSDK_MEMCHECK=ON \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\""

# DIAGNOSTIC COMMANDS

show-env:
  echo "$C_COMPILER"
  echo "$GENERATOR"
  echo "$ATDIRECTORY_HOST"
  echo "$ATDIRECTORY_PORT"
  echo "$FIRST_ATSIGN"
  echo "$FIRST_ATSIGN_ATSERVER_HOST"
  echo "$FIRST_ATSIGN_ATSERVER_PORT"
  echo "$SECOND_ATSIGN"
  echo "$SECOND_ATSIGN_ATSERVER_HOST"
  echo "$SECOND_ATSIGN_ATSERVER_PORT"
