# BUILDING

This project: **An Encryption Library**
Version: **0.0.1**

## Local build

```bash
# one-shot build + install
./build.sh install
```

Or run the steps manually:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j"$(nproc || sysctl -n hw.ncpu || echo 4)"
sudo cmake --install .
```



## Install dependencies (from `cmake.libraries`)


### System packages (required)

```bash
sudo apt-get update && sudo apt-get install -y libssl-dev
```



### Development tooling (optional)

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip valgrind gdb perl autoconf automake libtool
```



### OpenSSL

Install via package manager:

```bash
sudo apt-get update && sudo apt-get install -y libssl-dev
```

