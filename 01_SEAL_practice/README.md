# Try out SEAL

## Prerequisite

- Require **Clang++ (>= 5.0) or GNU G++ (>= 6.0), CMake (>= 3.13)** (build [cmake](https://github.com/Kitware/CMake.git) from source)

## Install SEAL

- Local install SEAL library

```
cd HE_practice/01_SEAL_practice/
git submodule update --init --recursive
cd SEAL/
git checkout 6bfac481aae4057ea887d42eb0f24371e9b4c4f9
cmake -S . -B build -DSEAL_BUILD_EXAMPLES=ON -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF -DCMAKE_INSTALL_PREFIX=~/mylibs
cmake --build build
cmake --install build
```

- There are examples under `SEAL/native/examples/` and the built binary is in `SEAL/build/bin/`, one can go through those files to have better grasp of HE operations.

## Test ourselves

- Test file `HE_practice/01_SEAL_practice/example/test.cpp`

```
cd HE_practice/01_SEAL_practice/example
cmake . -DCMAKE_PREFIX_PATH=~/mylibs  // install library first
cmake --build .
./test
```

## MNIST example

- folder structure
    - ```
      .
      ├── CMakeLists.txt  // cmake file
      ├── data.h          // model weight
      ├── gen_input.py    // preprocess mnist data (output MNIST.txt)
      ├── mnist_bfv.cpp   // BFV example
      ├── mnist_ckks.cpp  // CKKS example
      ├── MNIST.txt       // dumped data
      ├── print_parms.h   // helper functions
      └── train.py        // train the mnist
      ```

```
cd HE_practice/01_SEAL_practice/mnist
unzip input.zip
cmake . -DCMAKE_PREFIX_PATH=~/mylibs  // install library first
cmake --build .
./mnist_bfv
./mnist_ckks
```

- reference implementation
    - [LoLa](https://arxiv.org/pdf/1812.10659.pdf)
    - [Reference implementation](./mnist/20210305.pdf)
    - [Video](https://tinyurl.com/pnhxmhbt)

## Challenge

- [idash 2021 Track 2](http://www.humangenomeprivacy.org/2021/competition-tasks.html)
- dataset is under `challenge`, unzip it and you can start the challenge
