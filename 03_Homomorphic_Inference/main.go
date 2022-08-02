package main

import (
	"fmt"
	//"github.com/tuneinsight/lattigo/v3/ckks"
	//"github.com/tuneinsight/lattigo/v3/rlwe"
	//"github.com/tuneinsight/lattigo/v3/utils"
)

func Make2D[T any](n, m int) [][]T {
	matrix := make([][]T, n)
	for i := range matrix {
		matrix[i] = make([]T, m)
	}
	return matrix
}

func pneumonia() {
	/*var err error

	// Schemes parameters are created from scratch
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:         14,
		LogQ:         []int{31,26,26,26,26,26,26},
		LogP:         []int{31},
		Sigma:        rlwe.DefaultSigma,
		LogSlots:     13,
		DefaultScale: float64(1 << 26),
	})

	if err != nil {
		panic(err)
	}

	// Encoder
	encoder := ckks.NewEncoder(params)

	// Keys
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 2)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})

	// Print logs
	fmt.Printf("CKKS parameters: logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n",
		params.LogN(), params.LogQP(), params.MaxLevel()+1, params.DefaultScale(), params.Sigma())
	fmt.Println()


	values := make([]float64, params.Slots())

	// Prepare input
	encrypted_matrix := make([]*ckks.Ciphertext, 25)
	for p := 0; p < 5; p++ {
		for q := 0; q < 5; q++ {
			var k int = 0;
			var which int = p*5+q;
			for z := 0; z < params.Slots(); z++ {
				values[z] = 0
			}
			for i, ii := 0, p; i < 13; ii, i = ii+2, i+1 {
				for j, jj := 0, q; j < 13; jj,j = jj+2, j+1 {
					values[k] = input[ii][jj]
					k++
				}
			}
			plaintext := encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
			encrypted_matrix[which] = encryptor.EncryptNew(plaintext)
		}
	}

	// Prepare CNN weights
	cnn_weight := Make2D[*ckks.Plaintext](5, 25)
	for i := 0; i < 5; i++ {
		for j := 0; j < 25; j++ {
			for k := 0; k < params.Slots(); k++ {
				values[k] = conv1[i][j]
			}
			cnn_weight[i][j] = encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
		}
	}

	// First CNN_layer
	multiply_cnn := Make2D[*ckks.Ciphertext](5, 25)
	// 25*5 multiply plain
	for t := 0; t < 1; t++ {
		for i := 0; i < 25; i++ {
			fmt.Println(t, i)
			cipher_temp := evaluator.MulNew(encrypted_matrix[i], cnn_weight[t][i]);
			multiply_cnn[t][i] = cipher_temp
		}
	}

	// Encryption process
	tmp := encoder.Decode(decryptor.DecryptNew(multiply_cnn[0][0]), params.LogSlots())

	valuesTest := make([]float64, len(tmp))
	for i := range tmp {
		valuesTest[i] = real(tmp[i])
	}

	fmt.Println()
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	*/fmt.Println()
}

func main() {
	pneumonia()
}
