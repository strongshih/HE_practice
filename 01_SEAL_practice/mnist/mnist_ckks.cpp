#include "print_parms.h"
#include "seal/seal.h"
#include "data.h"
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
#define VERBOSE 1
#define NUM_THREAD 16

using namespace std;
using namespace seal;

// __int128 modInverse(__int128 a, __int128 m)
// {
//   for (__int128 x = 1; x < m; x++)
//     if (((a%m) * (x%m)) % m == 1)
//       return x;
// }

// static inline long int scale(double p, long int mod, double scale) {
//   long int temp = (long int)(p*scale); // scale = 32
//   temp = temp % mod;
//   temp = temp < 0 ? temp + mod : temp;
//   return temp; 
// }

class PlainWeights {
public:
  shared_ptr<SEALContext> contexts;
  EncryptionParameters parms;
  PublicKey public_keys;
  SecretKey secret_keys;
  RelinKeys relin_keys;
  GaloisKeys gal_keys;
  int slot_count;
  int num_dense_to_10;
  int reduce10_time;
    
  // weights
  vector<vector<Plaintext>> cnn_weights;
  vector<Plaintext> dense_to_100_matrices;
  Plaintext mask_plains;
  Plaintext bias_100_plains;
  Plaintext weight_10_plains;

  // Initialization Keys, vectors
  PlainWeights (size_t poly_modulus_degree) {
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();
    slot_count = poly_modulus_degree/2;
    num_dense_to_10 = 100/(slot_count/1024);

    EncryptionParameters parm(scheme_type::ckks);
    parm.set_poly_modulus_degree(poly_modulus_degree);
    parm.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {31,26,26,26,26,26,26,31}));
    parms = parm;

    SEALContext context(parms);
    contexts = make_shared<SEALContext>(context);

#ifdef VERBOSE
    print_parameters(contexts);
    cout << endl;
#endif
      
    KeyGenerator keygen(*(contexts.get()));
    secret_keys = keygen.secret_key();
    keygen.create_public_key(public_keys);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(gal_keys);
    
    CKKSEncoder batch_encoder(*(contexts.get()));
    Evaluator evaluator(*(contexts.get()));

    vector<double> allocated_vectors(slot_count, 0);
    Plaintext temp_plain;
    Ciphertext temp_cipher;
    
    // Prepare CNN weights
    vector<vector<Plaintext>> cnn_weight(5);
    for (int c = 0; c < 5; c++) {
      vector<Plaintext> one_channel_weights(25);
      for (int i = 0; i < 25; i++) {
        batch_encoder.encode(conv1[c][i], (double)pow(2.0, 26), temp_plain);
        one_channel_weights[i] = temp_plain;
      }
      cnn_weight[c] = one_channel_weights;
    }
    cnn_weights = cnn_weight;
    
    // Prepare 845x100 matrix
    vector<Plaintext> dense_to_100_matrix(num_dense_to_10);
    for (int i = 0; i < num_dense_to_10; i++) {
      allocated_vectors.assign(slot_count, 0);
      for (int j = 0; j < (slot_count/1024); j++) {
        for (int k = 0; k < 845; k++) {
          allocated_vectors[j*1024 + k] = fc1[i*(slot_count/1024)+j][k];
        }
      }
      batch_encoder.encode(allocated_vectors, (double)pow(2.0, 26), temp_plain);
      evaluator.mod_switch_to_next_inplace(temp_plain);
      evaluator.mod_switch_to_next_inplace(temp_plain);
      dense_to_100_matrix[i] = temp_plain;
    }
    dense_to_100_matrices = dense_to_100_matrix;

    // Prepare mask
    Plaintext mask_plain;
    allocated_vectors.assign(slot_count, 0);
    for (int j = 0; j < slot_count; j += 1024)
      allocated_vectors[j] = 1;
    batch_encoder.encode(allocated_vectors, (double)pow(2.0, 26), mask_plain);
    evaluator.mod_switch_to_next_inplace(mask_plain);
    evaluator.mod_switch_to_next_inplace(mask_plain);
    evaluator.mod_switch_to_next_inplace(mask_plain);
    mask_plains = mask_plain;

    // Prepare 100 bias
    Plaintext bias_100_plain;
    allocated_vectors.assign(slot_count, 0);
    for (int i = 0; i < 100; i++) {
      allocated_vectors[((i*1024)/slot_count) + (i*1024)%slot_count] = fc1_bias[i];
    }
    batch_encoder.encode(allocated_vectors, (double)pow(2.0, 26), bias_100_plain);
    evaluator.mod_switch_to_next_inplace(bias_100_plain);
    evaluator.mod_switch_to_next_inplace(bias_100_plain);
    evaluator.mod_switch_to_next_inplace(bias_100_plain);
    evaluator.mod_switch_to_next_inplace(bias_100_plain);
    bias_100_plains = bias_100_plain;

    int temp = 1;
    for (int i = 0; i < 10; i++) {
      if (num_dense_to_10 < (temp << i)) {
        reduce10_time = i;
        temp = (temp << i);
        break;
      }
    }
    
    // Prepare Dense to 10
    Plaintext weight_10_plain;
    allocated_vectors.assign(slot_count, 0);
    for (int i = 0; i < 10; i++) {
      for (int j = 0; j < 100; j++) {
        allocated_vectors[((j*1024)/slot_count) + (j*1024)%slot_count + temp*i] = fc2[i][j];
      }
    }
    batch_encoder.encode(allocated_vectors, (double)pow(2.0, 26), weight_10_plain);
    evaluator.mod_switch_to_next_inplace(weight_10_plain);
    evaluator.mod_switch_to_next_inplace(weight_10_plain);
    evaluator.mod_switch_to_next_inplace(weight_10_plain);
    evaluator.mod_switch_to_next_inplace(weight_10_plain);
    evaluator.mod_switch_to_next_inplace(weight_10_plain);
    weight_10_plains = weight_10_plain;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Initialization [" << time_diff.count() << " microseconds]" << endl;
  }

  // Encrypt Image
vector<Ciphertext> Encrypt_Image(double input[29][29]) {
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();

    vector<Ciphertext> encrypted_matrix(25);
    vector<double> allocated_vectors(slot_count, 0);
    Plaintext temp_plain;
    Ciphertext temp_cipher;

    Encryptor encryptor(*(contexts.get()), public_keys);
    CKKSEncoder batch_encoder(*(contexts.get()));

    #pragma omp parallel for num_threads(NUM_THREAD) private(temp_cipher, temp_plain, allocated_vectors) schedule(dynamic)
    for (int p = 0; p < 5; p++) {
      #pragma omp parallel for num_threads(NUM_THREAD) private(temp_cipher, temp_plain, allocated_vectors) schedule(dynamic)
      for (int q = 0; q < 5; q++) {
        int k = 0;
        int which = p*5+q;
        allocated_vectors.assign(slot_count, 0);
        for (int i = 0, ii = 0+p; i < 13; ii+=2, i++) {
          for (int j = 0, jj = 0+q; j < 13; jj+=2, j++) {
            allocated_vectors[k] = input[ii][jj]; 
            k++;
          }
        }
        batch_encoder.encode(allocated_vectors, (double)pow(2.0, 26), temp_plain);
        encryptor.encrypt(temp_plain, temp_cipher);
        encrypted_matrix[which] = temp_cipher;
      }
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Encrypt Image [" << time_diff.count() << " microseconds]" << endl;

    return encrypted_matrix;
  }
  
  int Inference (vector<Ciphertext> encrypted_matrix) {
    Plaintext temp_plain;
    Ciphertext temp_cipher;
    
    CKKSEncoder batch_encoder(*(contexts.get()));
    Decryptor decryptor(*(contexts.get()), secret_keys);

    temp_cipher = CNN(encrypted_matrix);
    temp_cipher = Square(temp_cipher);
    temp_cipher = Dense100(temp_cipher);
    temp_cipher = Square(temp_cipher);
    temp_cipher = Dense10(temp_cipher);
    decryptor.decrypt(temp_cipher, temp_plain);

    vector<double> final_result;
    batch_encoder.decode(temp_plain, final_result);

    double max = -100000;
    int max_idx = 0;
    for (int i = 0; i < 10; i++) {
#ifdef VERBOSE
      cout << final_result[(1 << reduce10_time)*i] << " ";
#endif
      if (final_result[(1 << reduce10_time)*i] > max) {
        max = final_result[(1 << reduce10_time)*i];
        max_idx = i;
      }
    }
#ifdef VERBOSE
    cout << endl;
#endif

    return max_idx;    
  }

  Ciphertext CNN(vector<Ciphertext> encrypted_matrix) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    Evaluator evaluator(*(contexts.get()));

    vector<vector<Ciphertext>> multiply_cnn(5, vector<Ciphertext> (25));

    // 25*5 multiply plain
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int t = 0; t < 5; t++)
      #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
      for (int i = 0; i < 25; i++) {
        evaluator.multiply_plain(encrypted_matrix[i], cnn_weights[t][i], multiply_cnn[t][i]);
        evaluator.rescale_to_next_inplace(multiply_cnn[t][i]);
      }

    // 24*5 addition
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int t = 0; t < 5; t++)
      for (int i = 1; i < 25; i++)
        evaluator.add_inplace(multiply_cnn[t][0], multiply_cnn[t][i]);
    
    // 4 rotate
    #pragma omp parallel for num_threads(NUM_THREAD) schedule(dynamic)
    for (int i = 1; i < 5; i++)
      evaluator.rotate_vector_inplace(multiply_cnn[i][0], -169*i, gal_keys);

    // 4 adds
    for (int i = 1; i < 5; i++)
      evaluator.add_inplace(multiply_cnn[0][0], multiply_cnn[i][0]);

#ifdef VERBOSE
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "CNN [" << time_diff.count() << " microseconds]" << endl;
#endif

    return multiply_cnn[0][0];
  }

  Ciphertext Square(Ciphertext input) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    Evaluator evaluator(*(contexts.get()));

    evaluator.square_inplace(input);
    evaluator.relinearize_inplace(input, relin_keys);
    evaluator.rescale_to_next_inplace(input);

#ifdef VERBOSE
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Square [" << time_diff.count() << " microseconds]" << endl;
#endif

    return input;
  }

  Ciphertext Dense100(Ciphertext input) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    Evaluator evaluator(*(contexts.get()));

    Ciphertext rotated_2;
    Ciphertext temp_cipher;
    for (int i = 1024; i <= slot_count/2; i*=2) {
      evaluator.rotate_vector(input, -i, gal_keys, temp_cipher);
      evaluator.add_inplace(input, temp_cipher);
    }

    vector<Ciphertext> after_dense_to_100_matrix(num_dense_to_10);

    #pragma omp parallel for num_threads(NUM_THREAD) private(temp_cipher) schedule(dynamic)
    for (int i = 0; i < num_dense_to_10; i++) {
      evaluator.multiply_plain(input, dense_to_100_matrices[i], temp_cipher); 
      evaluator.rescale_to_next_inplace(temp_cipher);
      after_dense_to_100_matrix[i] = temp_cipher;
    }
    
    #pragma omp parallel for num_threads(NUM_THREAD) private(temp_cipher) schedule(dynamic)
    for (int i = 0; i < num_dense_to_10; i++) {
      for (int j = 9; j >= 0; j--) {
        evaluator.rotate_vector(after_dense_to_100_matrix[i], (1 << j), gal_keys, temp_cipher);
        evaluator.add_inplace(after_dense_to_100_matrix[i], temp_cipher);
      }
      evaluator.multiply_plain_inplace(after_dense_to_100_matrix[i], mask_plains);
      evaluator.rescale_to_next_inplace(after_dense_to_100_matrix[i]); // we can let mask = 2**10 for selected position, (MSB of 2**10 should be correct) 
                                                                       // however, after square it becomes 2**20, we surely can schedule prime 2**(27+10)
                                                                       // to devide that 2**10, but additionally 10 out for 128 is inevitable.
      evaluator.rotate_vector_inplace(after_dense_to_100_matrix[i], -i, gal_keys);
    }
    
    for (int i = 1; i < num_dense_to_10; i++)
      evaluator.add_inplace(after_dense_to_100_matrix[0], after_dense_to_100_matrix[i]);

    after_dense_to_100_matrix[0].scale() = pow(2.0, 26);
    evaluator.add_plain_inplace(after_dense_to_100_matrix[0], bias_100_plains);

#ifdef VERBOSE
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dnese100 [" << time_diff.count() << " microseconds]" << endl;
#endif

    return after_dense_to_100_matrix[0];
  }

  Ciphertext Dense10(Ciphertext input) {

#ifdef VERBOSE
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
#endif

    Evaluator evaluator(*(contexts.get()));

    Ciphertext rotated_2;
    Ciphertext temp_cipher;
    
    // copy 4 times
    for (int i = (1 << reduce10_time), j = 0; j < 4; i*=2, j++) {
      evaluator.rotate_vector(input, -i, gal_keys, temp_cipher);
      evaluator.add_inplace(input, temp_cipher);
    }

    evaluator.multiply_plain_inplace(input, weight_10_plains);
    evaluator.rescale_to_next_inplace(input);

    // reduce sum over 1024 part
    for (int i = 1024; i <= slot_count/2; i*=2) {
      evaluator.rotate_vector(input, i, gal_keys, temp_cipher);
      evaluator.add_inplace(input, temp_cipher);
    }

    // reduce over 10
    int temp = 1;
    for (int i = 0; i < reduce10_time; i++) {
      evaluator.rotate_vector(input, temp, gal_keys, temp_cipher);
      evaluator.add_inplace(input, temp_cipher);
      temp *= 2;
    }
   
#ifdef VERBOSE
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dense10 [" << time_diff.count() << " microseconds]" << endl;
#endif

    return input;
  }
};

int main () {
  ifstream ifile("MNIST.txt", ios::in);
  
  if (!ifile.is_open()) {
      std::cerr << "There was a problem opening the input file!\n";
      exit(1);
  }

  PlainWeights plain(8192);
  vector<Ciphertext> encrypted_image;

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
