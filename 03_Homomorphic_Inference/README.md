## Setup

- Refer to [SEAL_pratice](https://github.com/strongshih/HE_practice/tree/main/01_SEAL_practice) and [Lattigo_practice](https://github.com/strongshih/HE_practice/tree/main/02_Lattigo_practice) to setup environment first
- Setup CUDA, CuDNN if want to train NN using GPU (check out [compatibility](https://docs.nvidia.com/deploy/cuda-compatibility/index.html) to install the right version)
	- [Setup NVIDIA driver](https://www.nvidia.com/en-us/drivers/unix/)
	- [Setup CUDA](https://developer.nvidia.com/cuda-downloads)
	- [Setup CuDNN](https://docs.nvidia.com/deeplearning/cudnn/install-guide/index.html)
- The setup for this practice: Ubuntu 20.04, Driver Version 470.129.06, CUDA Version: 11.4

## Knowledge distillation

- The practice is referenced from this [blog](https://www.analyticsvidhya.com/blog/2022/01/knowledge-distillation-theory-and-end-to-end-case-study/)
- Setup jupyter notebook
	- Install [miniconda](https://docs.conda.io/en/latest/miniconda.html#linux-installers)
	- Create virtualenv: `conda create --name myenv python=3.7`
	- `conda activate myenv`
- Install packages
	- `pip install notebook matplotlib tensorflow pandas opencv-python sklearn gdown`
- Download dataset 
	- `cd ~/HE_practice/03_Homomorphic_Inference`
	- `gdown --folder https://drive.google.com/drive/folders/1-6EPCvK56WybryyuiL31SZ8gKuFrzZOs`
	- `cd Lecture03-files`
	- `unzip chest_xray.zip`
- Jupyter notebook
	- `cd ~/HE_practice/03_Homomorphic_Inference`
	- `jupyter notebook`
	- `ssh user@server -N -L 8888:127.0.0.1:8888`
	- Open the browser `http://localhost:8888/tree`


- Train a teacher model then distill it to a HE-friendly student model
	- Go through the notebook

## Homomorphic inference through SEAL

```
cd ~/HE_practice/03_Homomorphic_Inference
cmake . -DCMAKE_PREFIX_PATH=~/mylibs
cmake --build .
./test
```

