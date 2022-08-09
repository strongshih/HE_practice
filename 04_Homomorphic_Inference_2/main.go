package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	//"github.com/tuneinsight/lattigo/v3/utils"
)

func pneumonia() {
	var err error

	// Schemes parameters are created from scratch
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:         15,
		LogQ:         []int{28, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26},
		LogP:         []int{28},
		Sigma:        rlwe.DefaultSigma,
		LogSlots:     14,
		DefaultScale: float64(1 << 26),
	})

	/*
	if err != nil {
		panic(err)
	}
	// Encoder
	encoder := ckks.NewEncoder(params)

	// Keys
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 2)
	rots := []int{1, -1, 2, -2, 4, -4, 8, -8, 16, -16, 32, -32, 64, -64, 128, -128, 256, -256, 512, -512, 1024, -1024, 2048, -2048, 4096, -4096, 8192}
	rotkey := kgen.GenRotationKeysForRotations(rots, true, sk)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotkey})

	// Print logs
	fmt.Printf("CKKS parameters: logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n",
		params.LogN(), params.LogQP(), params.MaxLevel()+1, params.DefaultScale(), params.Sigma())
	fmt.Println()


	plain_vector := make([]float64, params.Slots())

	// Prepare CNN1 weights
    var cnn1_weight [2][3][16]*ckks.Plaintext;
    for i := 0; i < 2; i++ {
	    for j := 0; j < 3; j++ {
		    for k := 0; k < 4; k++ {
			    for l := 0; l < 4; l++ {
					for m := range plain_vector { plain_vector[m] = CNN1[l][k][j][i] }
					cnn1_weight[i][j][k*4+l] = encoder.EncodeNew(plain_vector, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
                }
            }
        }
    }

	var cnn1_const [2]*ckks.Plaintext;
    for i := 0; i < 2; i++ {
		for m := range plain_vector { plain_vector[m] = CNN1_const[i] }
		cnn1_const[i] = encoder.EncodeNew(plain_vector, params.MaxLevel()-1, params.DefaultScale(), params.LogSlots())
    }

    // Second order activation (0.563059 + 0.5*x + 0.078047*x^2)
    var point_o_seven_mul *ckks.Plaintext;
	for m := range plain_vector { plain_vector[m] = 0.078047 }
	point_o_seven_mul = encoder.EncodeNew(plain_vector, params.MaxLevel()-2, params.DefaultScale(), params.LogSlots())

    var point_five_mul *ckks.Plaintext;
	for m := range plain_vector { plain_vector[m] = 0.5 }
	point_five_mul = encoder.EncodeNew(plain_vector, params.MaxLevel()-1, params.DefaultScale(), params.LogSlots())

    var point_five_add *ckks.Plaintext;
	for m := range plain_vector { plain_vector[m] = 0 }
    for i := 0; i < 27; i=i+1 {
        for j := 0; j < 111; j=j+1 {
            for k := 0; k < 4; k=k+1 {
                plain_vector[512*i+j*4+k] = 0.563059;
			}
		}
	}
	point_five_add = encoder.EncodeNew(plain_vector, params.MaxLevel()-3, params.DefaultScale(), params.LogSlots())



	// Prepare input
    var input_vector [3][16]*ckks.Ciphertext;
	for d := 0; d < 3; d=d+1 {
		for n := 0; n < 4; n=n+1 {
			for m := 0; m < 4; m=m+1 {
				for i :=0; i<params.Slots(); i++ {
					plain_vector[i] = 0;
				}
				for i := 0; i < 27; i=i+1 {
					for j := 0; j < 111; j=j+1 {
						for k := 0; k < 4; k=k+1 {
							plain_vector[512*i+j*4+k] = input_data[m+2*j][n+2*(k+4*i)][d];
						}
					}
				}
				plaintext := encoder.EncodeNew(plain_vector, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
				input_vector[d][n*4+m] = encryptor.EncryptNew(plaintext)
            }
        }
    }

	// Apply CNN1
	var after_cnn1 [2]*ckks.Ciphertext;
	var multiply_cnn1 [3*16]*ckks.Ciphertext;
    for i := 0; i < 2; i++ {
        for j := 0; j < 3; j++ {
            for k := 0; k < 16; k++ {
				multiply_cnn1[j*16+k] = evaluator.MulNew(input_vector[j][k], cnn1_weight[i][j][k])
				evaluator.Rescale(multiply_cnn1[j*16+k], params.DefaultScale(), multiply_cnn1[j*16+k])
            }
        }
        for j := 1; j < 3*16; j++ {
            evaluator.Add(multiply_cnn1[0], multiply_cnn1[j], multiply_cnn1[0]);
		}
        after_cnn1[i] = evaluator.AddNew(multiply_cnn1[0], cnn1_const[i]);
    }

    var after_act1 [2]*ckks.Ciphertext;
    var rotated_after_act1[2]*ckks.Ciphertext;
    for i := 0; i < 2; i++ {
        after_act1[i] = evaluator.MulNew(after_cnn1[i], point_five_mul);
        evaluator.Rescale(after_act1[i], params.DefaultScale(), after_act1[i]);
        evaluator.DropLevel(after_act1[i], 1);
        evaluator.Mul(after_cnn1[i], after_cnn1[i], after_cnn1[i]);
        evaluator.Relinearize(after_cnn1[i], after_cnn1[i]);
        evaluator.Rescale(after_cnn1[i], params.DefaultScale(), after_cnn1[i]);
        evaluator.Mul(after_cnn1[i], point_o_seven_mul, after_cnn1[i]);
        evaluator.Rescale(after_cnn1[i], params.DefaultScale(), after_cnn1[i]);
        evaluator.Add(after_act1[i], after_cnn1[i], after_act1[i]);
        evaluator.Add(after_act1[i], point_five_add, after_act1[i]);
        rotated_after_act1[i] = evaluator.RotateNew(after_act1[i], 8);
    }

	printOut(after_act1[1], decryptor, encoder, params.LogSlots())
	*/
}

func printOut(ciphertext *ckks.Ciphertext, decryptor ckks.Decryptor, encoder ckks.Encoder, slot_count int) {
	tmp := encoder.Decode(decryptor.DecryptNew(ciphertext), slot_count)

	valuesTest := make([]float64, len(tmp))
	for i := range tmp {
		valuesTest[i] = real(tmp[i])
	}

	fmt.Printf("Ciphertext level: %d\n", ciphertext.Level());
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f %6.10f...\n",
		valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3], valuesTest[4])
	fmt.Println()

}

func main() {
	pneumonia()
}
