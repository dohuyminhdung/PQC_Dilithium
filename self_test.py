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


def test_full_scheme(xi, msg, ctx):
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

def test_sample_in_ball():
    rho = b'\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA' * 8 #64 bytes
    out = ML_DSA_87.SampleInBall(rho)
    ans = out[::-1]
    print("SampleInBall output: \n", ans)

def test_rejection_NTT_poly():
    rho = b'\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA' * 4 + b'\xDD\xDD' #34 bytes
    out = ML_DSA_87.RejNTTPoly(rho)
    ans = out[::-1]
    print("Rejection_NTT_Poly output: \n", ans)

def test_rejection_bounded_poly():
    rho = b'\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA' * 8 + b'\xDD\xDD' #66 bytes
    out = ML_DSA_87.RejBoundedPoly(rho)
    ans = out[::-1]
    print("Rejection_Bounded_Poly output: \n", ans)

def test_expandA():
    rho = b'\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA' * 4  #32 bytes
    A = ML_DSA_87.ExpandA(rho)
    print("ExpandA output:")
    for row in A:
        print(row)

def test_expandS():
    rho = b'\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA' * 8  #64 bytes
    s1, s2 = ML_DSA_87.ExpandS(rho)
    print("ExpandS output (s1):")
    for row in s1:
        print(row)
    print("ExpandS output (s2):")
    for row in s2:
        print(row)

def test_expandMask():
    rho = b'\xef\xcd\xab\x90\x78\x56\x34\x12' * 8  #64 bytes
    mu = 1
    M = ML_DSA_87.ExpandMask(rho, mu)
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        i = 0
        print("ExpandMask output:")
        for row in M:
            for coeff in row:
                print(f"{i}: {coeff}")
                i += 1
        sys.stdout = sys.__stdout__ 

if __name__ == "__main__":
    # test_sample_in_ball()
    # test_rejection_NTT_poly()
    # test_rejection_bounded_poly()
    # test_expandA()
    # test_expandS()
    test_expandMask()
    # test_full_scheme(xi, msg, ctx)


