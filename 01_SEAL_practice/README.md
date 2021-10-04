# Try out SEAL

- Local install SEAL library

```
cd HE_practice/01_SEAL_practice/
git submodule update --init --recursive
cd SEAL/
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=~/mylibs
cmake --build build
cmake --install build
```

- Test

```
cd HE_practice/01_SEAL_practice/example
cmake . -DCMAKE_PREFIX_PATH=~/mylibs
make
./test
```
