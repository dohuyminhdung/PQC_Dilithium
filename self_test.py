from PQC import *
import sys
from Crypto.Hash import SHAKE256

ML_DSA_87 = Dilithium(rnd_seed_for_signing = 0, 
                      rnd = b'\x00' * 32,
                      print_matrix = 1)

xi = bytes([
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B,
    0x1C, 0x1D, 0x1E, 0x1F
])
msg = b"Hello Dilithium!"
ctx = b"test_vectors"


def test(xi, msg, ctx):
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        print_hex("m = : \n", msg)

        pk, sk = ML_DSA_87.KeyGen_internal(xi)
        print_hex("Public key: \n", pk)
        print_hex("Secret key: \n", sk)

        signature = ML_DSA_87.Sign(sk, msg, ctx)
        # signature = ML_DSA_87.Hash_Sign(sk, msg, ctx)
        print_hex("Signature: \n", signature)

        valid = ML_DSA_87.Verify(pk, msg, signature, ctx)
        # valid = ML_DSA_87.Hash_Verify(pk, msg, signature, ctx)
        print("Signature valid: ", str(valid))

        sys.stdout = sys.__stdout__ 

if __name__ == "__main__":
    test(xi, msg, ctx)



