from PQC import *
import sys
import random
import os

ML_DSA_87 = Dilithium(rnd_seed_for_signing = 1, 
                      rnd = b'\x00' * 32,
                      print_matrix=1)
ctx = b"test_vectors"
NTESTS = 1000
MIN_MSG_LEN = 10
MAX_MSG_LEN = 1000

if __name__ == "__main__":
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        for i in range(NTESTS):
            print(f"Test {i + 1}/{NTESTS}")

            MLEN = random.randint(MIN_MSG_LEN, MAX_MSG_LEN)  
            msg = os.urandom(MLEN)
            print_hex("message = : \n", msg)

            pk, sk = ML_DSA_87.KeyGen()
            print_hex("Public key: \n", pk)
            print_hex("Secret key: \n", sk)

            signature = ML_DSA_87.Sign(sk, msg, ctx)
            print_hex("Signature: \n", signature)
            if not ML_DSA_87.Verify(pk, msg, signature, ctx):
                print("Error: Signature verification failed!\n")
            
        sys.stdout = sys.__stdout__ 