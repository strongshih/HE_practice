package main

import (
	"fmt"
	"math"
	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

func innerProduct() {
	// https://github.com/tuneinsight/lattigo/blob/master/ckks/params.go#L49
	params, err := ckks.NewParametersFromLiteral(ckks.PN14QP438)
	if err != nil {
		panic(err)
	}

	// Encoder
	encoder := ckks.NewEncoder(params)

	// Keys
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	// Relinearization key
	rlk := kgen.GenRelinearizationKey(sk, 2)

	// Encryptor
	encryptor := ckks.NewEncryptor(params, pk)

	// Decryptor
	decryptor := ckks.NewDecryptor(params, sk)

	// Evaluator
	// See all the functions provided here: https://github.com/tuneinsight/lattigo/blob/master/ckks/evaluator.go#L23
	rots := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}
	rotkey := kgen.GenRotationKeysForRotations(rots, true, sk)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotkey})

	// Values to encrypt
	values := make([]float64, params.Slots())
	for i := range values {
		values[i] = float64(i)
	}

	// Print logs
	fmt.Printf("CKKS parameters: logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n",
		params.LogN(), params.LogQP(), params.MaxLevel()+1, params.DefaultScale(), params.Sigma())
	fmt.Println()
	fmt.Printf("Values     : %6f %6f %6f %6f...\n",
		(values[0]), (values[1]), (values[2]), (values[3]))
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())

	// Encryption process
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)

	//ciphertext := evaluator.MulRelinNew(ciphertext, ciphertext);
	evaluator.Mul(ciphertext, ciphertext, ciphertext)
	evaluator.Relinearize(ciphertext, ciphertext)
	evaluator.Rescale(ciphertext, params.DefaultScale(), ciphertext)

	//temp_cipher2 := NewCiphertext(evaluator.params, ciphertext.Degree(), ciphertext.Level(), ciphertext.Scale)
	for i := 16; i>0; i>>=1 {
		temp_cipher2 := evaluator.RotateNew(ciphertext, i);
		evaluator.Add(ciphertext, temp_cipher2, ciphertext);
	}

	fmt.Println("Done... Consumed levels:", params.MaxLevel()-ciphertext.Level())

	tmp := encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())

	valuesTest := make([]float64, len(tmp))
	for i := range tmp {
		valuesTest[i] = real(tmp[i])
	}

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Println()

}

func main() {
	innerProduct()
}
