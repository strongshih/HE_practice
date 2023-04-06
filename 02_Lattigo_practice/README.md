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
git checkout 93c14ff71ed9fb687bcfee76c1b850a7f487b573
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
rm go.sum go.mod
go mod init test                                                       // generate go.mod
go mod tidy                                                            // generate go.sum
go mod edit -replace github.com/tuneinsight/lattigo/v4=../lattigo/  // point to modified version
go run main.go data.go
```
