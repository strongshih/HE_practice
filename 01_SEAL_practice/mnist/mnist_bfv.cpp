#include "print_parms.h"
#include "seal/seal.h"
#include "data.h"
#include <cstdlib>
#include <omp.h>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#define VERBOSE
#define NUM_THREAD 8
#define NUM_PLAIN 4

using namespace std;
using namespace seal;

__int128 modInverse(__int128 a, __int128 m)
{
  for (__int128 x = 1; x < m; x++)
    if (((a%m) * (x%m)) % m == 1)
      return x;
}

static inline long int scale(double p, long int mod, double scale) {
  long int temp = (long int)(p*scale); // scale = 32
  temp = temp % mod;
  temp = temp < 0 ? temp + mod : temp;
  return temp; 
}

class PlainWeights {
public:
  array<shared_ptr<SEALContext>, NUM_PLAIN> contexts;
  array<EncryptionParameters, NUM_PLAIN> parms;
  array<PublicKey, NUM_PLAIN> public_keys;
  array<SecretKey, NUM_PLAIN> secret_keys;
  array<RelinKeys, NUM_PLAIN> relin_keys;
  array<GaloisKeys, NUM_PLAIN> gal_keys;
  int slot_count;

  // weights
  array<vector<vector<Plaintext>>, NUM_PLAIN> cnn_weights;
  array<vector<Plaintext>, NUM_PLAIN> dense_to_100_matrices;
  array<Plaintext, NUM_PLAIN> mask_plains;
  array<Plaintext, NUM_PLAIN> bias_100_plains;
  array<Plaintext, NUM_PLAIN> weight_10_plains;

  // CRT 
  array<long int, NUM_PLAIN> mods;
  array<__int128, NUM_PLAIN> mul;
  array<__int128, NUM_PLAIN> mul_inverse;
  __int128 t = 1;

  // Initialization Keys, vectors
  PlainWeights (size_t poly_modulus_degree, vector<long int> mods_input) {
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();
    slot_count = poly_modulus_degree;

    for (int i = 0; i < NUM_PLAIN; i++) {
      mods[i] = mods_input[i];
      t *= mods[i];
    }
    
    for (int i = 0; i < NUM_PLAIN; i++) {
      __int128 acc = 1;
      for (int j = 0; j < NUM_PLAIN; j++) {
        if (i == j) continue;
        acc *= (__int128)mods[j];
      }
      mul[i] = acc;
      mul_inverse[i] = modInverse(acc, mods[i]);
    }

    #pragma omp parallel for num_threads(NUM_THREAD) schedule(static)
    for (int n = 0; n < NUM_PLAIN; n++) {
      EncryptionParameters parm(scheme_type::bfv);
      parm.set_poly_modulus_degree(poly_modulus_degree);
      parm.set_coeff_modulus({2147565569, 2148155393, 2148384769, 2148728833, 2148794369, 2149072897, 2149171201});
      parm.set_plain_modulus(mods[n]);

      parms[n] = parm;
      SEALContext context(parms[n]);
      contexts[n] = make_shared<SEALContext>(context);

#ifdef VERBOSE
      print_parameters(contexts[n]);
      cout << endl;
#endif
      KeyGenerator keygen(context);
      secret_keys[n] = keygen.secret_key();
      keygen.create_public_key(public_keys[n]);
      keygen.create_relin_keys(relin_keys[n]);
      keygen.create_galois_keys(gal_keys[n]);
 
      BatchEncoder batch_encoder(context);
      Evaluator evaluator(context);

      vector<uint64_t> allocated_vectors(slot_count, 0);
      Plaintext temp_plain(16*slot_count, slot_count);
      Ciphertext temp_cipher;
      
      // Prepare CNN weights
      vector<vector<Plaintext>> cnn_weight(5);
      for (int c = 0; c < 5; c++) {
        vector<Plaintext> one_channel_weights;
        for (int i = 0; i < 25; i++) {
          long int temp = scale(conv1[c][i], mods[n], (double)(1LL << 5));
          temp_plain[0] = temp;
          one_channel_weights.push_back(temp_plain);
        }
        cnn_weight[c] = one_channel_weights;
      }
      cnn_weights[n] = cnn_weight;
      
      // Prepare 845x100 matrix
      vector<Plaintext> dense_to_100_matrix(13);
      for (int i = 0; i < 12; i++) {
        allocated_vectors.assign(slot_count, 0);
        for (int j = 0; j < 8; j++) {
          for (int k = 0; k < 845; k++) {
            long int temp = scale(fc1[i*8+j][k], mods[n], (double)(1LL << 5));
            allocated_vectors[j*1024 + k] = temp;
          }
        }
        batch_encoder.encode(allocated_vectors, temp_plain);
        dense_to_100_matrix[i] = temp_plain;
      }
      allocated_vectors.assign(slot_count, 0);
      for (int j = 0; j < 4; j++) {
        for (int k = 0; k < 845; k++) {
          long int temp = scale(fc1[12*8+j][k], mods[n], (double)(1LL << 5));
          allocated_vectors[j*1024 + k] = temp;
        }
      }
      batch_encoder.encode(allocated_vectors, temp_plain);
      dense_to_100_matrix[12] = temp_plain;
      dense_to_100_matrices[n] = dense_to_100_matrix;

      // Prepare mask
      Plaintext mask_plain;
      allocated_vectors.assign(slot_count, 0);
      for (int j = 0; j < slot_count; j += 1024)
        allocated_vectors[j] = 1;
      batch_encoder.encode(allocated_vectors, mask_plain);
      mask_plains[n] = mask_plain;

      // Prepare 100 bias
      Plaintext bias_100_plain;
      allocated_vectors.assign(slot_count, 0);
      for (int i = 0; i < 100; i++) {
        long int temp = scale(fc1_bias[i], mods[n], (double)(1LL << 23));
        allocated_vectors[((i*1024)/slot_count) + (i*1024)%slot_count] = temp;
      }
      batch_encoder.encode(allocated_vectors, bias_100_plain);
      bias_100_plains[n] = bias_100_plain;

      // Prepare Dense to 10
      Plaintext weight_10_plain;
      allocated_vectors.assign(slot_count, 0);
      for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 100; j++) {
          long int temp = scale(fc2[i][j], mods[n], (double)(1LL << 5));
          allocated_vectors[((j*1024)/slot_count) + (j*1024)%slot_count + 16*i] = temp;
        }
      }
      batch_encoder.encode(allocated_vectors, weight_10_plain);
      weight_10_plains[n] = weight_10_plain;
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Initialization [" << time_diff.count() << " microseconds]" << endl;
  }

  // Encrypt Image
  vector<vector<Ciphertext>> Encrypt_Image(double input[29][29]) {
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();

    vector<vector<Ciphertext>> encrypted_matrices(NUM_PLAIN);

    #pragma omp parallel for num_threads(NUM_THREAD) schedule(static)
    for (int n = 0; n < NUM_PLAIN; n++) {
      vector<Ciphertext> encrypted_matrix(25);
      vector<uint64_t> allocated_vectors(slot_count, 0);
      Plaintext temp_plain;
      Ciphertext temp_cipher;

      SEALContext *c = contexts[n].get();
      Encryptor encryptor(*c, public_keys[n]);
      BatchEncoder batch_encoder(*c);

      #pragma omp parallel for num_threads(NUM_THREAD) private(temp_cipher, temp_plain, allocated_vectors) schedule(dynamic)
      for (int p = 0; p < 5; p++) {
        #pragma omp parallel for num_threads(NUM_THREAD) private(temp_cipher, temp_plain, allocated_vectors) schedule(dynamic)
        for (int q = 0; q < 5; q++) {
          int k = 0;
          int which = p*5+q;
          allocated_vectors.assign(slot_count, 0);
          for (int i = 0, ii = 0+p; i < 13; ii+=2, i++) {
            for (int j = 0, jj = 0+q; j < 13; jj+=2, j++) {
              long int temp = scale(input[ii][jj], mods[n], (double)(1LL << 4));
              allocated_vectors[k] = temp; 
              k++;
            }
          }
          batch_encoder.encode(allocated_vectors, temp_plain);
          encryptor.encrypt(temp_plain, temp_cipher);
          encrypted_matrix[which] = temp_cipher;
        }
      }
      encrypted_matrices[n] = encrypted_matrix;

#ifdef VERBOSE
      Decryptor decryptor(*c, secret_keys[n]);
      // cout << "Noise budget (after Encrypt):  " << decryptor.invariant_noise_budget(encrypted_matrix[0]) << " bits" << endl;
#endif

    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Encrypt Image [" << time_diff.count() << " microseconds]" << endl;

    return encrypted_matrices;
  }
  
  int Inference (vector<vector<Ciphertext>> encrypted_matrices) {
    vector<vector<uint64_t>> outcome(NUM_PLAIN);  
    vector<Ciphertext> temp_cipher(NUM_PLAIN);

    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int n = 0; n < NUM_PLAIN; n++) {
      temp_cipher[n] = CNN(encrypted_matrices[n], n);
    }
    
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int n = 0; n < NUM_PLAIN; n++) {
      temp_cipher[n] = Square(temp_cipher[n], n);
    }
    
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int n = 0; n < NUM_PLAIN; n++) {
      temp_cipher[n] = Dense100(temp_cipher[n], n);
    }

    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int n = 0; n < NUM_PLAIN; n++) {
      temp_cipher[n] = Square(temp_cipher[n], n);
    }
    
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int n = 0; n < NUM_PLAIN; n++) {
      temp_cipher[n] = Dense10(temp_cipher[n], n);
    }
    
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int n = 0; n < NUM_PLAIN; n++) {
      Plaintext temp_plain;
      SEALContext *c = contexts[n].get();
      BatchEncoder batch_encoder(*c);
      Decryptor decryptor(*c, secret_keys[n]);
      decryptor.decrypt(temp_cipher[n], temp_plain);

      vector<uint64_t> pod_result;
      batch_encoder.decode(temp_plain, pod_result);
      outcome[n]=pod_result;
    }

    // CRT
    vector<double> final_result = CRT_Reconstruct(outcome);

    double max = -100000;
    int max_idx = 0;
    for (int i = 0; i < 10; i++) {
#ifdef VERBOSE
      cout << final_result[16*i] << " ";
#endif
      if (final_result[16*i] > max) {
        max = final_result[16*i];
        max_idx = i;
      }
    }
#ifdef VERBOSE
    cout << endl;
#endif

    return max_idx;    
  }

  vector<double> CRT_Reconstruct(vector<vector<uint64_t>> outcome) {
#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    vector<double> final_result(slot_count);

    // CRT reconstruct
    double s = (double)(1LL << 51);
    for (int i = 0; i < slot_count; i++) {
      __int128 temp = 0;
      for (int j = 0; j < NUM_PLAIN; j++) {
        temp += ((__int128)outcome[j][i])*mul[j]*mul_inverse[j];
      }
      temp = temp % t;
      temp = temp > t/2 ? temp-t : temp;
      final_result[i] = (double)(temp)/s;
    }

#ifdef VERBOSE
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "CRT [" << time_diff.count() << " microseconds]" << endl;
#endif

    return final_result;
  }

  Ciphertext CNN(vector<Ciphertext> encrypted_matrix, int which) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    SEALContext *c = contexts[which].get();
    Evaluator evaluator(*c);

    vector<vector<Ciphertext>> multiply_cnn(5, vector<Ciphertext> (25));

    // 25*5 multiply plain
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int t = 0; t < 5; t++)
      #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
      for (int i = 0; i < 25; i++)
        evaluator.multiply_plain(encrypted_matrix[i], cnn_weights[which][t][i], multiply_cnn[t][i]); 

    // 24*5 addition
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int t = 0; t < 5; t++)
      for (int i = 1; i < 25; i++)
        evaluator.add_inplace(multiply_cnn[t][0], multiply_cnn[t][i]);

    // 4 rotate
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int i = 1; i < 5; i++)
      evaluator.rotate_rows_inplace(multiply_cnn[i][0], -169*i, gal_keys[which]);

    // 4 adds
    for (int i = 1; i < 5; i++)
      evaluator.add_inplace(multiply_cnn[0][0], multiply_cnn[i][0]);

#ifdef VERBOSE
    Decryptor decryptor(*c, secret_keys[which]);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "CNN [" << time_diff.count() << " microseconds]" << endl;
    // cout << "Noise budget (after CNN):  " << decryptor.invariant_noise_budget(multiply_cnn[0][0]) << " bits" << endl;
#endif

    return multiply_cnn[0][0];
  }

  Ciphertext Square(Ciphertext input, int which) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    SEALContext *c = contexts[which].get();
    Evaluator evaluator(*c);

    evaluator.square_inplace(input);
    evaluator.relinearize_inplace(input, relin_keys[which]);
    evaluator.mod_switch_to_next_inplace(input);

#ifdef VERBOSE
    Decryptor decryptor(*c, secret_keys[which]);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Square [" << time_diff.count() << " microseconds]" << endl;
    // cout << "Noise budget (after Square):  " << decryptor.invariant_noise_budget(input) << " bits" << endl;
#endif

    return input;
  }

  Ciphertext Dense100(Ciphertext input, int which) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    SEALContext *c = contexts[which].get();
    Evaluator evaluator(*c);

    // 845 copy 8 times [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4]
    Ciphertext rotated_2;
    Ciphertext rotated_4;
    Ciphertext rotated_8;
    Ciphertext rotated_16;
    Ciphertext temp_cipher;
    evaluator.rotate_rows(input, -1024, gal_keys[which], rotated_2);
    evaluator.add_inplace(rotated_2, input);
    evaluator.rotate_rows(rotated_2, -2048, gal_keys[which], rotated_4);
    evaluator.add_inplace(rotated_4, rotated_2);
    evaluator.rotate_columns(rotated_4, gal_keys[which], rotated_8);
    evaluator.add_inplace(rotated_8, rotated_4);

    vector<Ciphertext> after_dense_to_100_matrix(13);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dense100_1 [" << time_diff.count() << " microseconds]" << endl;

    time_start = chrono::high_resolution_clock::now();

#pragma omp parallel num_threads(NUM_THREAD)
{
    #pragma omp for private(temp_cipher) schedule(dynamic)
    for (int i = 0; i < 13; i++) {
      evaluator.multiply_plain(i == 12 ? rotated_8 : rotated_8, dense_to_100_matrices[which][i], temp_cipher); 
      evaluator.mod_switch_to_next_inplace(temp_cipher);
      after_dense_to_100_matrix[i] = temp_cipher;
      for (int j = 9; j >= 0; j--) {
        evaluator.rotate_rows(after_dense_to_100_matrix[i], (1 << j), gal_keys[which], temp_cipher);
        evaluator.add_inplace(after_dense_to_100_matrix[i], temp_cipher);
      }
      evaluator.multiply_plain_inplace(after_dense_to_100_matrix[i], mask_plains[which]);
      evaluator.mod_switch_to_next_inplace(after_dense_to_100_matrix[i]);
      evaluator.rotate_rows_inplace(after_dense_to_100_matrix[i], -i, gal_keys[which]);
    }
}

    
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dense100_2 [" << time_diff.count() << " microseconds]" << endl;

    time_start = chrono::high_resolution_clock::now();

    for (int i = 1; i < 13; i++)
      evaluator.add_inplace(after_dense_to_100_matrix[0], after_dense_to_100_matrix[i]);

    evaluator.add_plain_inplace(after_dense_to_100_matrix[0], bias_100_plains[which]);

#ifdef VERBOSE
    Decryptor decryptor(*c, secret_keys[which]);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dense100_3 [" << time_diff.count() << " microseconds]" << endl;
    // cout << "Noise budget (after Dense100):  " << decryptor.invariant_noise_budget(after_dense_to_100_matrix[0]) << " bits" << endl;
#endif

    return after_dense_to_100_matrix[0];
  }

  Ciphertext Dense10(Ciphertext input, int which) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    SEALContext *c = contexts[which].get();
    Evaluator evaluator(*c);

    Ciphertext rotated_2;
    Ciphertext rotated_4;
    Ciphertext rotated_8;
    Ciphertext rotated_16;
    
    // copy 4 times
    evaluator.rotate_rows(input, -16, gal_keys[which], rotated_2);
    evaluator.add_inplace(rotated_2, input);
    evaluator.rotate_rows(rotated_2, -32, gal_keys[which], rotated_4);
    evaluator.add_inplace(rotated_4, rotated_2);
    evaluator.rotate_rows(rotated_4, -64, gal_keys[which], rotated_8);
    evaluator.add_inplace(rotated_8, rotated_4);
    evaluator.rotate_rows(rotated_8, -128, gal_keys[which], rotated_16);
    evaluator.add_inplace(rotated_16, rotated_8);

    Ciphertext after_10_rot;
    evaluator.multiply_plain_inplace(rotated_16, weight_10_plains[which]);
    evaluator.rotate_columns(rotated_16, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);
    evaluator.rotate_rows(rotated_16, 2048, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);
    evaluator.rotate_rows(rotated_16, 1024, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);
    evaluator.mod_switch_to_next_inplace(rotated_16);
    evaluator.rotate_rows(rotated_16, 8, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);
    evaluator.rotate_rows(rotated_16, 4, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);
    evaluator.rotate_rows(rotated_16, 2, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);
    evaluator.rotate_rows(rotated_16, 1, gal_keys[which], after_10_rot);
    evaluator.add_inplace(rotated_16, after_10_rot);

#ifdef VERBOSE
    Decryptor decryptor(*c, secret_keys[which]);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dense10 [" << time_diff.count() << " microseconds]" << endl;
    // cout << "Noise budget (after Dense10):  " << decryptor.invariant_noise_budget(rotated_16) << " bits" << endl;
#endif

    return rotated_16;
  }
};

int main () {
  ifstream ifile("MNIST.txt", ios::in);
  
  if (!ifile.is_open()) {
      std::cerr << "There was a problem opening the input file!\n";
      exit(1);
  }

  vector<long int> primes{65537, 114689, 147457, 163841};
  PlainWeights plain(8192, primes);
  vector<vector<Ciphertext>> encrypted_image;

  omp_set_nested(1);
  omp_set_num_threads(NUM_THREAD);
  
  double temp;
  double input[29][29];
  int cnt = 0;
  int correct = 0;
  int sample = 0;

  unsigned int total = 0;

  while (ifile >> temp) {
    if (cnt < 29*29) {
      input[cnt/29][cnt%29] = temp;
      cnt += 1;
    }
    else {
      encrypted_image = plain.Encrypt_Image(input);
      
      chrono::high_resolution_clock::time_point time_start, time_end;
      chrono::microseconds time_diff;
      time_start = chrono::high_resolution_clock::now();
    
      int out = plain.Inference(encrypted_image);

      time_end = chrono::high_resolution_clock::now();
      time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
      cout << "Inference Image [" << time_diff.count() << " microseconds]" << endl;
      total += time_diff.count();

      if ((int)out == (int)temp) {
        correct += 1;
      }
      sample += 1;
      cout << correct << "/" << sample << endl;
      cnt = 0;
    }
  }

  cout << "NUM_THREAD: " << NUM_THREAD << ", average time: " << total / (float)cnt << ", over " << cnt << " time";
}
