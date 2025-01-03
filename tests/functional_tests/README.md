# tests/functional_tests

## Description

This directory contains functional tests for at_c. These tests utilize the virtual environment to run atServers and an atDirectory server to simulate a close production level environment. 

## Prerequisites

In order to run the functional tests you will need to have the following installed:

1. Docker Compose 1.29.2+ (any version should work though)

2. CMake 3.24+

## Running The Tests

1. Clone the repository

2. Copy the contents of the `keys/` directory into your system's atsign keys folder (`~/.atsign/keys/`).

The following command should do the trick:

```bash
cd tests/functional_tests/tools/virtualenv/keys
cp -r * ~/.atsign/keys/
```

3. Add `vip.ve.atsign.zone` to your `/etc/hosts` file. This is necessary for the tests to run.

```bash
echo "127.0.0.1 vip.ve.atsign.zone" | sudo tee -a /etc/hosts
```

4. Navigate to the `tests/functional_tests/tools/virtualenv` directory. This directory has some tools for starting up the virtual environment.

```bash
cd tests/functional_tests/tools/virtualenv
```

5. Run the `start_virtualenv.sh` script. This script will start up the virtual environment. You may need to use `sudo`.

```bash
./start_virtualenv.sh
```

6. After a few seconds, the virtual environment should be up and running. You should now run PKAM so that you are able to PKAM authenticate to any of the atServers.

```bash
./pkam_virtualenv.sh
```

7. Now you can run the tests. Navigate back to the `tests/functional_tests/tools` directory.

```bash
cd ../
```

8. Run the `build.sh` script. This script will build the tests.

```bash
./build.sh
```

9. Run the `ctest.sh` script which will run ctest on the built binaries.

```bash
./ctest.sh
```

The last few lines of the output should look something like this:

```
100% tests passed, 0 tests failed out of 9

Total Test time (real) =  19.99 sec
```
