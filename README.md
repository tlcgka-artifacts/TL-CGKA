# TL-CGKA

This repository contains the C and Python implementations of TL-CGKA presented in our paper, together with the [security models and complete proofs](proofs/Security%20Models%20and%20Proofs.pdf). Both implementations support group key updates, core member joins and leaves, and ordinary member joins and leaves.

## Deployment

The commands below assume Ubuntu 24.04 (including WSL) and start in the repository root. Each implementation can be installed independently.

### C

Install a C11 compiler, CMake, OpenSSL and libsodium, then build the shared library and command-line program.

```sh
sudo apt update
sudo apt install build-essential cmake libssl-dev libsodium-dev
cmake -S c -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Run the key update, core membership and ordinary membership examples. The arguments specify the initial group size, number of subgroups, core members per subgroup and update rounds per phase. These examples start with 16 members in two subgroups, with two core members per subgroup.

```sh
./build/tlcgka_cli demo 16 2 2 3
./build/tlcgka_cli membership 16 2 2 3
./build/tlcgka_cli ordinary-membership 16 2 2 3
ctest --test-dir build --output-on-failure
```

### Python

Install Python 3.11 or later and libsodium. Create a virtual environment and install the package with its Python dependencies.

```sh
sudo apt update
sudo apt install python3 python3-venv libsodium-dev
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./python
```

Run the membership example and the test suite. The example updates a group key, adds and removes a core member, then adds and removes an ordinary member. Each phase reports the group size and checks that all active members share the same key.

```sh
python python/demo.py
python -m unittest discover -s python/tests
```
