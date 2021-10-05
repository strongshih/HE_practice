// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
using namespace std;
using namespace seal;

int main()
{
    /** Perform inner product [0.000, 0.001, ..., 2.047] * [2.047,
     *                                                      2.046,
     *                                                        ...,
     *                                                      0.001,
     *                                                      0.000]
     **/
    
    size_t poly_modulus_degree = 4096; // Q = 109
    int slot_count = poly_modulus_degree/2;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {38, 33, 38}));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;  // for enc/dec
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;  // for HMul
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;   // for rotation
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder batch_encoder(context);
   
    Plaintext temp_plain;
    Ciphertext temp_cipher;
    vector<double> plain_vector(slot_count, 0);
    for (int i = 0; i < slot_count; i++)
        plain_vector[i] = (double)i * 0.001;
    batch_encoder.encode(plain_vector, (double)pow(2.0, 33), temp_plain);
    encryptor.encrypt(temp_plain, temp_cipher);
    /** temp_cipher
     *   _______________________________________________
     *  | 0.001*2^33 | 0.002*2^33 | ... | 0.2047 * 2^33 |
     *   -----------------------------------------------
     **/ 

    // Available operations
    // https://github.com/microsoft/SEAL/blob/main/native/src/seal/evaluator.h
    evaluator.square_inplace(temp_cipher);
    evaluator.relinearize_inplace(temp_cipher, relin_keys);
    evaluator.rescale_to_next_inplace(temp_cipher);
    /** temp_cipher
     *   ___________________________________________________________
     *  | (0.001*2^33)^2 | (0.002*2^33)^2 | ... | (0.2047 * 2^33)^2 |
     *   -----------------------------------------------------------
     **/ 

    // rotate left and add
    Ciphertext temp_cipher2;
    for (int i = 1024; i>0; i>>=1) {
        evaluator.rotate_vector(temp_cipher, i, gal_keys, temp_cipher2);
        evaluator.add_inplace(temp_cipher, temp_cipher2);
    }
    
    vector<double> results(slot_count, 0);
    decryptor.decrypt(temp_cipher, temp_plain);
    batch_encoder.decode(temp_plain, results);
    cout << "HE result:    " << results[0] << endl;

    double temp = 0.0;
    for (int i = 0; i < slot_count; i++)
        temp += (0.001 * (float)i * 0.001 * (float)i);
    cout << "Plain result: " << results[0] << endl;

    return 0;
}
