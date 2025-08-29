from PQC import *
import sys
import random
import os

ML_DSA_87 = Dilithium()
ctx = b"test_dilithium"
NTESTS = 10000

if __name__ == "__main__":

    valid_signature_tests = 0
    invalid_signature_tests = 0

    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        for i in range(NTESTS):
            MLEN = random.randint(10, 10000)  
            msg = os.urandom(MLEN)

            pk, sk = ML_DSA_87.KeyGen()
            signature = ML_DSA_87.Sign(sk, msg, ctx)
            if ML_DSA_87.Verify(pk, msg, signature, ctx):
                valid_signature_tests += 1
            
            signature_list = list(signature)
            idx = random.randint(0, len(signature_list) - 1)
            b =  random.randint(0, 255)

            while b == signature_list[idx]:
                b = random.randint(0, 255)
            signature_list[idx] = b

            tampered_signature = bytes(signature_list)
            if not ML_DSA_87.Verify(pk, msg, tampered_signature, ctx):
                invalid_signature_tests += 1

        print(f"Valid signature tests: {valid_signature_tests} / {NTESTS}, pass {valid_signature_tests / NTESTS * 100:.2f}%")
        print(f"Invalid signature tests: {invalid_signature_tests} / {NTESTS}, pass {invalid_signature_tests / NTESTS * 100:.2f}%")
        sys.stdout = sys.__stdout__ 