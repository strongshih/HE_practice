package main

import (
	"fmt"
	"math"
	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	//"github.com/tuneinsight/lattigo/v3/utils"
)

func innerProduct() {
	var err error

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
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})

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
	evaluator.MulRelin(ciphertext, ciphertext, ciphertext);
	evaluator.Rescale(ciphertext, params.DefaultScale(), ciphertext);

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
