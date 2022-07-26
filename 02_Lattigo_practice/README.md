# Try out Lattigo

## Prerequisite

- Install go

```
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-go
```

- Add path to `~/.bashrc` (check the go version, here 1.18), and `source` it

```
export GOROOT=/usr/lib/go-1.18
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```


## Test Lattigo

- Install

```
cd HE_practice/02_Lattigo_practice/
git submodule update --init
cd lattigo
git checkout 8df1d3bed79e315f527c1c5fc9704f5df9de0f11
```

- Test

```
make
```

## Try out Lattigo

-  `02_Lattigo_practice/example`

```
cd 02_Lattigo_practice/example
go run main.go
```

## Mnist translation

```
cd 02_Lattigo_practice/mnist
go run main.go data.go
```
