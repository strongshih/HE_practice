// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include "weights.h"
#include "x_tests.h"
#include "y_tests.h"
#include "input_data.h"
using namespace std;
using namespace seal;

int main()
{
    int precision = 26;
    size_t poly_modulus_degree = 32768; // Q = 418
    int slot_count = poly_modulus_degree/2;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {28, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 28}));

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
    vector<vector<Ciphertext>> input_vector(3, vector<Ciphertext> (16));
    
    // Prepare CNN1 weights
    vector<vector<vector<Plaintext>>> cnn1_weight(2, vector<vector<Plaintext>> (3, vector<Plaintext> (16)));
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 4; k++) {
                for (int l = 0; l < 4; l++) {
                    batch_encoder.encode(CNN1[l][k][j][i], (double)pow(2.0, precision), temp_plain);
                    cnn1_weight[i][j][k*4+l] = temp_plain;
                }
            }
        }
    }
    vector<Plaintext> cnn1_const(2);
    for (int i = 0; i < 2; i++) {
        batch_encoder.encode(CNN1_const[i], (double)pow(2.0, precision), temp_plain);
        evaluator.mod_switch_to_next_inplace(temp_plain);
        cnn1_const[i] = temp_plain;
    }

    // Second order activation (0.563059 + 0.5*x + 0.078047*x^2)
    Plaintext point_o_seven_mul;
    batch_encoder.encode(0.078047, (double)pow(2.0, precision), point_o_seven_mul);
    for (int i = 0; i < 2; i++) evaluator.mod_switch_to_next_inplace(point_o_seven_mul);

    Plaintext point_five_mul;
    batch_encoder.encode(0.5, (double)pow(2.0, precision), point_five_mul);
    evaluator.mod_switch_to_next_inplace(point_five_mul);

    Plaintext point_five_add;
    plain_vector.assign(slot_count, 0);
    for (int i = 0; i < 27; i=i+1)
        for (int j = 0; j < 111; j=j+1)
            for (int k = 0; k < 4; k=k+1)
                plain_vector[512*i+j*4+k] = 0.563059;
    batch_encoder.encode(plain_vector, (double)pow(2.0, precision), point_five_add);
    for (int i = 0; i < 3; i++) evaluator.mod_switch_to_next_inplace(point_five_add);
 
    // Prepare CNN2 weights
    vector<vector<Plaintext>> cnn2_weight(4, vector<Plaintext>(2));
    for (int n = 0; n < 4; n++) {
        for (int m = 0; m < 2; m++) {
            plain_vector.assign(slot_count, 0);
            for (int i = 0; i < 27; i++) {
                for (int j = 0; j < 27; j++) {
                    for (int k = 0; k < 4; k++) {
                        for (int l = 0; l < 4; l++) {
                            plain_vector[512*i+16*j+4*k+l] = CNN2[k][l][m][n];
                        }
                    }
                }
            }
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 3; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            cnn2_weight[n][m] = temp_plain;
        }
    }
    vector<vector<Plaintext>> cnn2_weight2(4, vector<Plaintext>(2));
    for (int n = 0; n < 4; n++) {
        for (int m = 0; m < 2; m++) {
            plain_vector.assign(slot_count, 0);
            for (int i = 0; i < 27; i++) {
                for (int j = 0; j < 27; j++) {
                    for (int k = 0; k < 4; k++) {
                        for (int l = 0; l < 4; l++) {
                            plain_vector[512*i+16*j+4*k+l] = CNN2[k][(l+2)%4][m][n];
                        }
                    }
                }
            }
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 3; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            cnn2_weight2[n][m] = temp_plain;
        }
    }

    vector<Plaintext> cnn2_const(4);
    for (int i = 0; i < 4; i++) {
        batch_encoder.encode(CNN2_const[i], (double)pow(2.0, precision), temp_plain);
        for (int i = 0; i < 4; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
        cnn2_const[i] = temp_plain;
    }
    
    // Second order activation (0.563059 + 0.5*x + 0.078047*x^2)
    Plaintext point_o_seven_mul_2;
    batch_encoder.encode(0.078047, (double)pow(2.0, precision), point_o_seven_mul_2);
    for (int i = 0; i < 5; i++) evaluator.mod_switch_to_next_inplace(point_o_seven_mul_2);

    Plaintext point_five_mul_2;
    batch_encoder.encode(0.5, (double)pow(2.0, precision), point_five_mul_2);
    for (int i = 0; i < 4; i++) evaluator.mod_switch_to_next_inplace(point_five_mul_2);

    Plaintext point_five_add_2;
    batch_encoder.encode(0.563059, (double)pow(2.0, precision), point_five_add_2);
    for (int i = 0; i < 6; i++) evaluator.mod_switch_to_next_inplace(point_five_add_2);
    
     // Prepare CNN3 weights
    vector<vector<Plaintext>> cnn3_weight_00(8, vector<Plaintext>(4));
    vector<vector<Plaintext>> cnn3_weight_01(8, vector<Plaintext>(4));
    vector<vector<Plaintext>> cnn3_weight_10(8, vector<Plaintext>(4));
    vector<vector<Plaintext>> cnn3_weight_11(8, vector<Plaintext>(4));
    for (int n = 0; n < 8; n++) {
        for (int m = 0; m < 4; m++) {
            plain_vector.assign(slot_count, 0);
            for (int i = 0; i < 27; i++) {
                for (int j = 0; j < 27; j++) {
                    plain_vector[512*i+16*j] = CNN3[2*(j%2)][2*(i%2)][m][n];
                }
            }
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 6; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            cnn3_weight_00[n][m] = temp_plain;

            plain_vector.assign(slot_count, 0);
            for (int i = 0; i < 27; i++) {
                for (int j = 0; j < 27; j++) {
                    plain_vector[512*i+16*j] = CNN3[2*(j%2)+1][2*(i%2)][m][n];
                }
            }
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 6; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            cnn3_weight_01[n][m] = temp_plain;

            plain_vector.assign(slot_count, 0);
            for (int i = 0; i < 27; i++) {
                for (int j = 0; j < 27; j++) {
                    plain_vector[512*i+16*j] = CNN3[2*(j%2)][2*(i%2)+1][m][n];
                }
            }
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 6; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            cnn3_weight_10[n][m] = temp_plain;

            plain_vector.assign(slot_count, 0);
            for (int i = 0; i < 27; i++) {
                for (int j = 0; j < 27; j++) {
                    plain_vector[512*i+16*j] = CNN3[2*(j%2)+1][2*(i%2)+1][m][n];
                }
            }
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 6; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            cnn3_weight_11[n][m] = temp_plain;
        }
    }
    vector<Plaintext> cnn3_const(8);
    for (int n = 0; n < 8; n++) {
        batch_encoder.encode(CNN3_const[n], (double)pow(2.0, precision), temp_plain);
        for (int i = 0; i < 7; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
        cnn3_const[n] = temp_plain;
    }
    
     // Second order activation (0.563059 + 0.5*x + 0.078047*x^2)
    Plaintext point_o_seven_mul_3;
    batch_encoder.encode(0.078047, (double)pow(2.0, precision), point_o_seven_mul_3);
    for (int i = 0; i < 8; i++) evaluator.mod_switch_to_next_inplace(point_o_seven_mul_3);

    Plaintext point_five_mul_3;
    batch_encoder.encode(0.5, (double)pow(2.0, precision), point_five_mul_3);
    for (int i = 0; i < 7; i++) evaluator.mod_switch_to_next_inplace(point_five_mul_3);

    Plaintext point_five_add_3;
    batch_encoder.encode(0.563059, (double)pow(2.0, precision), point_five_add_3);
    for (int i = 0; i < 9; i++) evaluator.mod_switch_to_next_inplace(point_five_add_3);

    
    Plaintext mask;
    plain_vector.assign(slot_count, 0);
    for (int i = 0; i < 13; i++) {
        for (int j = 0; j < 13; j++) {
            plain_vector[i*1024+32*j] = 0.25;
        }
    }
    batch_encoder.encode(plain_vector, (double)pow(2.0, precision), mask);
    for (int i = 0; i < 9; i++) evaluator.mod_switch_to_next_inplace(mask);
    
     // prepare denseto256
    vector<Plaintext> dense1_weight(32);
    for (int i = 0; i < 32; i++) {
        plain_vector.assign(slot_count, 0);
        for (int jj=0; jj<2; jj++) {
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 8; k++) {
                    for (int n = 0; n < 13; n++) {
                        for (int m = 0; m < 13; m++) {
                            plain_vector[512*jj+32*m+1024*n+8*j+k] = dense1[104*m+8*n+k][i*8+(j+jj*4)];
                        }
                    }
                }
            }
        }
        batch_encoder.encode(plain_vector, (double)pow(2.0, precision), dense1_weight[i]);
        for (int n = 0; n < 10; n++) evaluator.mod_switch_to_next_inplace(dense1_weight[i]);
    }    
    vector<Plaintext> dense1_c(32);
    for (int i = 0; i < 32; i++) {
        plain_vector.assign(slot_count, 0);
        for (int jj = 0; jj < 2; jj++) {
            for (int j = 0; j < 4; j++) {
                plain_vector[jj*512+8*j] = dense1_const[8*i+jj*4+j];
            }
        } 
        batch_encoder.encode(plain_vector, (double)pow(2.0, precision), dense1_c[i]);
        for (int n = 0; n < 11; n++) evaluator.mod_switch_to_next_inplace(dense1_c[i]);
    }

    // Second order activation (0.563059 + 0.5*x + 0.078047*x^2)
    Plaintext point_o_seven_mul_4;
    batch_encoder.encode(0.078047, (double)pow(2.0, precision), point_o_seven_mul_4);
    for (int i = 0; i < 12; i++) evaluator.mod_switch_to_next_inplace(point_o_seven_mul_4);

    Plaintext point_five_mul_4;
    batch_encoder.encode(0.5, (double)pow(2.0, precision), point_five_mul_4);
    for (int i = 0; i < 11; i++) evaluator.mod_switch_to_next_inplace(point_five_mul_4);

    Plaintext point_five_add_4;
    batch_encoder.encode(0.563059, (double)pow(2.0, precision), point_five_add_4);
    for (int i = 0; i < 13; i++) evaluator.mod_switch_to_next_inplace(point_five_add_4);
    
    vector<vector<Plaintext>> dense2_w(2, vector<Plaintext>(32));
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 32; j++) {
            plain_vector.assign(slot_count, 0);
            for (int jj = 0; jj < 2; jj++) {
                for (int k = 0; k < 4; k++) {
                    plain_vector[jj*512+8*k] = dense2[8*j+jj*4+k][i];
                }
            } 
            batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
            for (int i = 0; i < 13; i++) evaluator.mod_switch_to_next_inplace(temp_plain);
            dense2_w[i][j] = temp_plain;
        }
    }






    int correct = 0;
    for (int kkk = 0; kkk < 10; kkk++) {
    for (int d = 0; d < 3; d=d+1) {
        for (int n = 0; n < 4; n=n+1) {
            for (int m = 0; m < 4; m=m+1) {
                plain_vector.assign(slot_count, 0);
                for (int i = 0; i < 27; i=i+1) {
                    for (int j = 0; j < 111; j=j+1) {
                        for (int k = 0; k < 4; k=k+1) {
                            plain_vector[512*i+j*4+k] = x_test[kkk][m+2*j][n+2*(k+4*i)][d];
                            //plain_vector[512*i+j*4+k] = input_data[m+2*j][n+2*(k+4*i)][d];
                        }
                    }
                }
                batch_encoder.encode(plain_vector, (double)pow(2.0, precision), temp_plain);
                encryptor.encrypt(temp_plain, temp_cipher);
                input_vector[d][n*4+m] = temp_cipher;
            }
        }
    }

    // Apply CNN1
    vector<Ciphertext> after_cnn1(2);
    vector<Ciphertext> multiply_cnn1(3*16);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 16; k++) {
                evaluator.multiply_plain(input_vector[j][k], cnn1_weight[i][j][k], temp_cipher);
                evaluator.rescale_to_next_inplace(temp_cipher);
                multiply_cnn1[j*16+k] = temp_cipher;
            }
        }
        for (int j = 1; j < 3*16; j++) 
            evaluator.add_inplace(multiply_cnn1[0], multiply_cnn1[j]);
        multiply_cnn1[0].scale() = pow(2.0, precision);
        evaluator.add_plain_inplace(multiply_cnn1[0], cnn1_const[i]);
        after_cnn1[i] = multiply_cnn1[0];
    }
    
    vector<Ciphertext> after_act1(2);
    vector<Ciphertext> rotated_after_act1(2);
    for (int i = 0; i < 2; i++) {
        evaluator.multiply_plain(after_cnn1[i], point_five_mul, after_act1[i]);
        evaluator.rescale_to_next_inplace(after_act1[i]);
        evaluator.mod_switch_to_next_inplace(after_act1[i]);
        evaluator.square_inplace(after_cnn1[i]);
        evaluator.relinearize_inplace(after_cnn1[i], relin_keys);
        evaluator.rescale_to_next_inplace(after_cnn1[i]);
        evaluator.multiply_plain_inplace(after_cnn1[i], point_o_seven_mul);
        evaluator.rescale_to_next_inplace(after_cnn1[i]);
        after_cnn1[i].scale() = pow(2.0, precision);
        after_act1[i].scale() = pow(2.0, precision);
        evaluator.add_inplace(after_act1[i], after_cnn1[i]);
        evaluator.add_plain_inplace(after_act1[i], point_five_add);
        evaluator.rotate_vector(after_act1[i], 8, gal_keys, rotated_after_act1[i]);
    }
    

  
    vector<Ciphertext> after_cnn2_0_0(4);
    vector<Ciphertext> after_cnn2_0_1(4);
    vector<Ciphertext> after_cnn2_1_0(4);
    vector<Ciphertext> after_cnn2_1_1(4);
    vector<Ciphertext> multiply_cnn2(2);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            evaluator.multiply_plain(after_act1[j], cnn2_weight[i][j], multiply_cnn2[j]);
            evaluator.rescale_to_next_inplace(multiply_cnn2[j]);
        }
        evaluator.add(multiply_cnn2[0], multiply_cnn2[1], after_cnn2_0_0[i]);
        evaluator.rotate_vector(after_cnn2_0_0[i], 8, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_0[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_0_0[i], 4, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_0[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_0_0[i], 2, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_0[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_0_0[i], 1, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_0[i], temp_cipher);
        after_cnn2_0_0[i].scale() = pow(2.0, precision);
        evaluator.add_plain_inplace(after_cnn2_0_0[i], cnn2_const[i]);
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            evaluator.multiply_plain(rotated_after_act1[j], cnn2_weight[i][j], multiply_cnn2[j]);
            evaluator.rescale_to_next_inplace(multiply_cnn2[j]);
        }
        evaluator.add(multiply_cnn2[0], multiply_cnn2[1], after_cnn2_0_1[i]);
        evaluator.rotate_vector(after_cnn2_0_1[i], 8, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_1[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_0_1[i], 4, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_1[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_0_1[i], 2, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_1[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_0_1[i], 1, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_0_1[i], temp_cipher);
        after_cnn2_0_1[i].scale() = pow(2.0, precision);
        evaluator.add_plain_inplace(after_cnn2_0_1[i], cnn2_const[i]);
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            evaluator.multiply_plain(after_act1[j], cnn2_weight2[i][j], multiply_cnn2[j]);
            evaluator.rescale_to_next_inplace(multiply_cnn2[j]);
        }
        evaluator.add(multiply_cnn2[0], multiply_cnn2[1], after_cnn2_1_0[i]);
        evaluator.rotate_vector(after_cnn2_1_0[i], 8, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_1_0[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_1_0[i], 4, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_1_0[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_1_0[i], 512, gal_keys, temp_cipher);
        evaluator.rotate_vector_inplace(temp_cipher,-2, gal_keys);
        evaluator.add_inplace(after_cnn2_1_0[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_1_0[i], 1, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_1_0[i], temp_cipher);
        after_cnn2_1_0[i].scale() = pow(2.0, precision);
        evaluator.add_plain_inplace(after_cnn2_1_0[i], cnn2_const[i]);
        evaluator.rotate_vector_inplace(after_cnn2_1_0[i], 2, gal_keys);
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            evaluator.multiply_plain(rotated_after_act1[j], cnn2_weight2[i][j], multiply_cnn2[j]);
            evaluator.rescale_to_next_inplace(multiply_cnn2[j]);
        }
        evaluator.add(multiply_cnn2[0], multiply_cnn2[1], after_cnn2_1_1[i]);
        evaluator.rotate_vector(after_cnn2_1_1[i], 8, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_1_1[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_1_1[i], 4, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_1_1[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_1_1[i], 512, gal_keys, temp_cipher);
        evaluator.rotate_vector_inplace(temp_cipher,-2, gal_keys);
        evaluator.add_inplace(after_cnn2_1_1[i], temp_cipher);
        evaluator.rotate_vector(after_cnn2_1_1[i], 1, gal_keys, temp_cipher);
        evaluator.add_inplace(after_cnn2_1_1[i], temp_cipher);
        after_cnn2_1_1[i].scale() = pow(2.0, precision);
        evaluator.add_plain_inplace(after_cnn2_1_1[i], cnn2_const[i]);
        evaluator.rotate_vector_inplace(after_cnn2_1_1[i], 2, gal_keys);
    }

    
    // after_act2
    vector<Ciphertext> after_act2_0_0(4);
    vector<Ciphertext> after_act2_0_1(4);
    vector<Ciphertext> after_act2_1_0(4);
    vector<Ciphertext> after_act2_1_1(4);
 
    vector<Ciphertext> after_act2(4);
    for (int i = 0; i < 4; i++) {
        evaluator.multiply_plain(after_cnn2_0_0[i], point_five_mul_2, after_act2_0_0[i]);
        evaluator.rescale_to_next_inplace(after_act2_0_0[i]);
        evaluator.mod_switch_to_next_inplace(after_act2_0_0[i]);
        evaluator.square_inplace(after_cnn2_0_0[i]);
        evaluator.relinearize_inplace(after_cnn2_0_0[i], relin_keys);
        evaluator.rescale_to_next_inplace(after_cnn2_0_0[i]);
        evaluator.multiply_plain_inplace(after_cnn2_0_0[i], point_o_seven_mul_2);
        evaluator.rescale_to_next_inplace(after_cnn2_0_0[i]);
        after_cnn2_0_0[i].scale() = pow(2.0, precision);
        after_act2_0_0[i].scale() = pow(2.0, precision);
        evaluator.add_inplace(after_act2_0_0[i], after_cnn2_0_0[i]);
        evaluator.add_plain_inplace(after_act2_0_0[i], point_five_add_2);
    }
    for (int i = 0; i < 4; i++) {
        evaluator.multiply_plain(after_cnn2_0_1[i], point_five_mul_2, after_act2_0_1[i]);
        evaluator.rescale_to_next_inplace(after_act2_0_1[i]);
        evaluator.mod_switch_to_next_inplace(after_act2_0_1[i]);
        evaluator.square_inplace(after_cnn2_0_1[i]);
        evaluator.relinearize_inplace(after_cnn2_0_1[i], relin_keys);
        evaluator.rescale_to_next_inplace(after_cnn2_0_1[i]);
        evaluator.multiply_plain_inplace(after_cnn2_0_1[i], point_o_seven_mul_2);
        evaluator.rescale_to_next_inplace(after_cnn2_0_1[i]);
        after_cnn2_0_1[i].scale() = pow(2.0, precision);
        after_act2_0_1[i].scale() = pow(2.0, precision);
        evaluator.add_inplace(after_act2_0_1[i], after_cnn2_0_1[i]);
        evaluator.add_plain_inplace(after_act2_0_1[i], point_five_add_2);
    }
    for (int i = 0; i < 4; i++) {
        evaluator.multiply_plain(after_cnn2_1_0[i], point_five_mul_2, after_act2_1_0[i]);
        evaluator.rescale_to_next_inplace(after_act2_1_0[i]);
        evaluator.mod_switch_to_next_inplace(after_act2_1_0[i]);
        evaluator.square_inplace(after_cnn2_1_0[i]);
        evaluator.relinearize_inplace(after_cnn2_1_0[i], relin_keys);
        evaluator.rescale_to_next_inplace(after_cnn2_1_0[i]);
        evaluator.multiply_plain_inplace(after_cnn2_1_0[i], point_o_seven_mul_2);
        evaluator.rescale_to_next_inplace(after_cnn2_1_0[i]);
        after_cnn2_1_0[i].scale() = pow(2.0, precision);
        after_act2_1_0[i].scale() = pow(2.0, precision);
        evaluator.add_inplace(after_act2_1_0[i], after_cnn2_1_0[i]);
        evaluator.add_plain_inplace(after_act2_1_0[i], point_five_add_2);
    }
    for (int i = 0; i < 4; i++) {
        evaluator.multiply_plain(after_cnn2_1_1[i], point_five_mul_2, after_act2_1_1[i]);
        evaluator.rescale_to_next_inplace(after_act2_1_1[i]);
        evaluator.mod_switch_to_next_inplace(after_act2_1_1[i]);
        evaluator.square_inplace(after_cnn2_1_1[i]);
        evaluator.relinearize_inplace(after_cnn2_1_1[i], relin_keys);
        evaluator.rescale_to_next_inplace(after_cnn2_1_1[i]);
        evaluator.multiply_plain_inplace(after_cnn2_1_1[i], point_o_seven_mul_2);
        evaluator.rescale_to_next_inplace(after_cnn2_1_1[i]);
        after_cnn2_1_1[i].scale() = pow(2.0, precision);
        after_act2_1_1[i].scale() = pow(2.0, precision);
        evaluator.add_inplace(after_act2_1_1[i], after_cnn2_1_1[i]);
        evaluator.add_plain_inplace(after_act2_1_1[i], point_five_add_2);
    }
       

    vector<vector<vector<Ciphertext>>> after_cnn3(8, vector<vector<Ciphertext>>(2, vector<Ciphertext>(2)));
    vector<Ciphertext> cnn3_temp0(4);
    vector<Ciphertext> cnn3_temp1(4);
    vector<Ciphertext> cnn3_temp2(4);
    vector<Ciphertext> cnn3_temp3(4);
    for (int i = 0; i < 8; i++) {
        for (int n = 0; n < 2; n++) {
            for (int m = 0; m < 2; m++) {
                for (int j = 0; j < 4; j++) {
                    cnn3_temp0[j] = after_act2_0_0[j];
                    cnn3_temp1[j] = after_act2_0_1[j];
                    cnn3_temp2[j] = after_act2_1_0[j];
                    cnn3_temp3[j] = after_act2_1_1[j];
                }
                if (m > 0) {
                    for (int j = 0; j < 4; j++) {
                        evaluator.rotate_vector_inplace(cnn3_temp0[j], 16, gal_keys);
                        evaluator.rotate_vector_inplace(cnn3_temp1[j], 16, gal_keys);
                        evaluator.rotate_vector_inplace(cnn3_temp2[j], 16, gal_keys);
                        evaluator.rotate_vector_inplace(cnn3_temp3[j], 16, gal_keys);
                    }
                }
                if (n > 0) {
                    for (int j = 0; j < 4; j++) {
                        evaluator.rotate_vector_inplace(cnn3_temp0[j], 512, gal_keys);
                        evaluator.rotate_vector_inplace(cnn3_temp1[j], 512, gal_keys);
                        evaluator.rotate_vector_inplace(cnn3_temp2[j], 512, gal_keys);
                        evaluator.rotate_vector_inplace(cnn3_temp3[j], 512, gal_keys);
                    }
                }
                for (int j = 0; j < 4; j++) {
                    evaluator.multiply_plain_inplace(cnn3_temp0[j], cnn3_weight_00[i][j]);
                    evaluator.multiply_plain_inplace(cnn3_temp1[j], cnn3_weight_01[i][j]);
                    evaluator.multiply_plain_inplace(cnn3_temp2[j], cnn3_weight_10[i][j]);
                    evaluator.multiply_plain_inplace(cnn3_temp3[j], cnn3_weight_11[i][j]);
                    evaluator.rescale_to_next_inplace(cnn3_temp0[j]);
                    evaluator.rescale_to_next_inplace(cnn3_temp1[j]);
                    evaluator.rescale_to_next_inplace(cnn3_temp2[j]);
                    evaluator.rescale_to_next_inplace(cnn3_temp3[j]);
                }
                for (int j = 1; j < 4; j++) {
                    evaluator.add_inplace(cnn3_temp0[0], cnn3_temp0[j]);
                    evaluator.add_inplace(cnn3_temp1[0], cnn3_temp1[j]);
                    evaluator.add_inplace(cnn3_temp2[0], cnn3_temp2[j]);
                    evaluator.add_inplace(cnn3_temp3[0], cnn3_temp3[j]);
                }
                evaluator.add_inplace(cnn3_temp0[0], cnn3_temp1[0]);
                evaluator.add_inplace(cnn3_temp0[0], cnn3_temp2[0]);
                evaluator.add_inplace(cnn3_temp0[0], cnn3_temp3[0]);
                evaluator.rotate_vector(cnn3_temp0[0], 16, gal_keys, temp_cipher);
                evaluator.add_inplace(cnn3_temp0[0], temp_cipher);
                evaluator.rotate_vector(cnn3_temp0[0], 512, gal_keys, temp_cipher);
                evaluator.add_inplace(cnn3_temp0[0], temp_cipher);
                cnn3_temp0[0].scale() = pow(2.0, precision);
                cnn3_const[i].scale() = pow(2.0, precision);
                evaluator.add_plain(cnn3_temp0[0], cnn3_const[i], after_cnn3[i][n][m]);
            }
        }
    }
    
    vector<vector<vector<Ciphertext>>> after_act3(8, vector<vector<Ciphertext>>(2, vector<Ciphertext>(2)));
    for (int i = 0; i < 8; i++) {
        for (int n = 0; n < 2; n++) {
            for (int m = 0; m < 2; m++) {
                evaluator.multiply_plain(after_cnn3[i][n][m], point_five_mul_3, after_act3[i][n][m]);
                evaluator.rescale_to_next_inplace(after_act3[i][n][m]);
                evaluator.mod_switch_to_next_inplace(after_act3[i][n][m]);
                evaluator.square_inplace(after_cnn3[i][n][m]);
                evaluator.relinearize_inplace(after_cnn3[i][n][m], relin_keys);
                evaluator.rescale_to_next_inplace(after_cnn3[i][n][m]);
                evaluator.multiply_plain_inplace(after_cnn3[i][n][m], point_o_seven_mul_3);
                evaluator.rescale_to_next_inplace(after_cnn3[i][n][m]);
                after_cnn3[i][n][m].scale() = pow(2.0, precision);
                after_act3[i][n][m].scale() = pow(2.0, precision);
                evaluator.add_inplace(after_act3[i][n][m], after_cnn3[i][n][m]);
                evaluator.add_plain_inplace(after_act3[i][n][m], point_five_add_3);
            }
        }
    }

    vector<Ciphertext> after_avg(8);
    for (int i = 0; i < 8; i++) {
        evaluator.add_inplace(after_act3[i][0][0], after_act3[i][0][1]);
        evaluator.add_inplace(after_act3[i][0][0], after_act3[i][1][0]);
        evaluator.add_inplace(after_act3[i][0][0], after_act3[i][1][1]);
        evaluator.multiply_plain(after_act3[i][0][0], mask, after_avg[i]);
        evaluator.rescale_to_next_inplace(after_avg[i]);
    }
    
    evaluator.rotate_vector_inplace(after_avg[1], -1, gal_keys);
    evaluator.rotate_vector_inplace(after_avg[3], -1, gal_keys);
    evaluator.rotate_vector_inplace(after_avg[5], -1, gal_keys);
    evaluator.rotate_vector_inplace(after_avg[7], -1, gal_keys);
    evaluator.add_inplace(after_avg[0], after_avg[1]);
    evaluator.add_inplace(after_avg[2], after_avg[3]);
    evaluator.add_inplace(after_avg[4], after_avg[5]);
    evaluator.add_inplace(after_avg[6], after_avg[7]);
    evaluator.rotate_vector_inplace(after_avg[2], -2, gal_keys);
    evaluator.rotate_vector_inplace(after_avg[6], -2, gal_keys);
    evaluator.add_inplace(after_avg[0], after_avg[2]);
    evaluator.add_inplace(after_avg[4], after_avg[6]);
    evaluator.rotate_vector_inplace(after_avg[4], -4, gal_keys);
    evaluator.add_inplace(after_avg[0], after_avg[4]);

    // copy 8 times
    evaluator.rotate_vector(after_avg[0], -8, gal_keys, temp_cipher);
    evaluator.add_inplace(after_avg[0], temp_cipher);
    evaluator.rotate_vector(after_avg[0], -16, gal_keys, temp_cipher);
    evaluator.add_inplace(after_avg[0], temp_cipher);
    evaluator.rotate_vector(after_avg[0], -512, gal_keys, temp_cipher);
    evaluator.add_inplace(after_avg[0], temp_cipher);

    vector<Ciphertext> after_dense1(32);
    for (int i = 0; i < 32; i++) {
        evaluator.multiply_plain(after_avg[0], dense1_weight[i], after_dense1[i]);
        evaluator.rescale_to_next_inplace(after_dense1[i]);
        evaluator.rotate_vector(after_dense1[i], 4, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 2, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 1, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 32, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 64, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 128, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 256, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 1024, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 2048, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 4096, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        evaluator.rotate_vector(after_dense1[i], 8192, gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense1[i], temp_cipher);
        after_dense1[i].scale() = pow(2.0, precision);
        dense1_c[i].scale() = pow(2.0, precision);
        evaluator.add_plain_inplace(after_dense1[i], dense1_c[i]);
    }

    vector<Ciphertext> after_act4(32);
    for (int i = 0; i < 32; i++) {
	evaluator.multiply_plain(after_dense1[i], point_five_mul_4, after_act4[i]);
	evaluator.rescale_to_next_inplace(after_act4[i]);
	evaluator.mod_switch_to_next_inplace(after_act4[i]);
	evaluator.square_inplace(after_dense1[i]);
	evaluator.relinearize_inplace(after_dense1[i], relin_keys);
	evaluator.rescale_to_next_inplace(after_dense1[i]);
	evaluator.multiply_plain_inplace(after_dense1[i], point_o_seven_mul_4);
	evaluator.rescale_to_next_inplace(after_dense1[i]);
	after_dense1[i].scale() = pow(2.0, precision);
	after_act4[i].scale() = pow(2.0, precision);
	evaluator.add_inplace(after_act4[i], after_dense1[i]);
	evaluator.add_plain_inplace(after_act4[i], point_five_add_4);
    }

    vector<double> ans(2);
    vector<Ciphertext> dense2_temp(32);
    vector<double> results(slot_count, 0);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 32; j++) {
            evaluator.multiply_plain(after_act4[j], dense2_w[i][j], dense2_temp[j]);
        }
        for (int j = 1; j < 32; j++) {
            evaluator.add_inplace(dense2_temp[0], dense2_temp[j]);
        }
        evaluator.rotate_vector(dense2_temp[0], 8, gal_keys, temp_cipher);
        evaluator.add_inplace(dense2_temp[0], temp_cipher);
        evaluator.rotate_vector(dense2_temp[0], 16, gal_keys, temp_cipher);
        evaluator.add_inplace(dense2_temp[0], temp_cipher);
        evaluator.rotate_vector(dense2_temp[0], 512, gal_keys, temp_cipher);
        evaluator.add_inplace(dense2_temp[0], temp_cipher);
        decryptor.decrypt(dense2_temp[0], temp_plain);
        batch_encoder.decode(temp_plain, results);
        cout << "Plain result " << i << ": " << results[0] << endl;
        ans[i] = results[0];
    }
    
    int idx = 0;
    if (ans[0] < ans[1]) {
        idx = 1;
    }
    int ans_idx = 0;
    if (y_test[kkk][0] < y_test[kkk][1]) {
        ans_idx = 1;
    }
    if (ans_idx == idx) {
        correct += 1;
    } 
    cout << correct << " / 10" << endl;
    
    }

    return 0;
}
