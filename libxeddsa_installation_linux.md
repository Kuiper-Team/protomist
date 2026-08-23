# How to Install libxeddsa on Linux
First, make sure libsodium is installed: https://libsodium.gitbook.io/doc/installation
Then clone the libxeddsa repository:
```bash
git clone https://github.com/Syndace/libxeddsa.git
```
cd into it:
```bash
cd libxeddsa
```
Build it:
```bash
mkdir build/
cd build/
cmake ..
make
```
Test it:
```bash
ctest ..
```
Install it:
```bash
cd ..
sudo cmake --install build
sudo install -Dm644 ./include/xeddsa.h /usr/local/include/xeddsa.h
sudo install -Dm644 ./ref10/include/cross_platform.h /usr/local/include/cross_platform.h
```
I wrote this because the documentation at https://libxeddsa.readthedocs.io/en/latest/installation.html seemed incomplete.
