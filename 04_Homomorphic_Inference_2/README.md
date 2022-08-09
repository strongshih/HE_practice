## Setup

- Refer to [SEAL_pratice](https://github.com/strongshih/HE_practice/tree/main/01_SEAL_practice) and [Lattigo_practice](https://github.com/strongshih/HE_practice/tree/main/02_Lattigo_practice) to setup environment first

## Homomorphic inference through SEAL

```
cd ~/HE_practice/04_Homomorphic_Inference_2
cmake . -DCMAKE_PREFIX_PATH=~/mylibs
cmake --build .
./main
```

## Homomorphic inference through Lattigo

```
go run *.go
```
