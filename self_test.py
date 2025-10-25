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

def decompose_lut():
    s1: str = ""
    s2: str = ""
    s3: str = ""
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        stage = -1
        minus = -1
        negative = -1
        negative_flag = 1
        for i in range(0, ML_DSA_87.q):
            r1, r0 = ML_DSA_87.Decompose(i)
            if r1 != stage:
                s1 += (f"i = {i}: HighBits = {r1}\n")
                stage = r1
            if minus != (i - r0)//(2*ML_DSA_87.gamma2):
                minus = (i - r0)//(2*ML_DSA_87.gamma2)
                s2 += (f"i = {i}: LowBits = {minus}\n")

            if negative_flag != (r0 < 0):
                negative = (i - r0)//(2*ML_DSA_87.gamma2)
                s3 += (f"i = {i}: r1 = {r1}, r0 = {r0}, LowBits = {negative}\n")
            negative_flag = (r0 < 0)
        print(s1)
        print(s2)
        print(s3)
        sys.stdout = sys.__stdout__

def use_hint_lut():
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        r1 = 0
        
        last_ans = -1
        h = 0
        print("Case 1: h = 0")
        for i in range(0, ML_DSA_87.q):
            r1 = ML_DSA_87.UseHint(h, i)
            if r1 != last_ans:
                print(f"r = {i} => r1 = {r1}")
                last_ans = r1

        last_ans = -1
        h = 1
        print("Case 2: h = 1")
        for i in range(0, ML_DSA_87.q):
            r1 = ML_DSA_87.UseHint(h, i)
            if r1 != last_ans:
                print(f"r = {i} => r1 = {r1}")
                last_ans = r1
        sys.stdout = sys.__stdout__

def test_sample_in_ball():
    rho = b'\xef\xcd\xab\x90\x78\x56\x34\x12' * 8  #64 bytes
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        i = 0
        c = ML_DSA_87.SampleInBall(rho)
        print("SampleInBall output:")
        for coeff in c:
            if(coeff < 0): print(f"{i}: {8380417 + coeff}")
            else: print(f"{i}: {coeff}")
            i += 1
        sys.stdout = sys.__stdout__

def test_expandA():
    rho = b'\xef\xcd\xab\x90\x78\x56\x34\x12' * 4  #32 bytes
    i = 0
    A = ML_DSA_87.ExpandA(rho)
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        print("ExpandA output:")
        for row in A:
            for poly in row:
                for coeff in poly:
                    print(f"{i}: {coeff}")
                    i = i + 1
        sys.stdout = sys.__stdout__ 

def test_expandS():
    rho = b'\xef\xcd\xab\x90\x78\x56\x34\x12' * 8  #64 bytes
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        i = 0
        s1, s2 = ML_DSA_87.ExpandS(rho)
        print("ExpandS output:")
        for row in s1:
            for coeff in row:
                if(coeff < 0): print(f"{i}: {8380417 + coeff}")
                else: print(f"{i}: {coeff}")
                i += 1
        for row in s2:
            for coeff in row:
                if(coeff < 0): print(f"{i}: {8380417 + coeff}")
                else: print(f"{i}: {coeff}")
                i += 1
        sys.stdout = sys.__stdout__ 

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
                if(coeff < 0): print(f"{i}: {8380417 + coeff}")
                else: print(f"{i}: {coeff}")
                i += 1
        sys.stdout = sys.__stdout__ 

def compare_output(file1, file2):
    with open(file1, 'r', encoding='utf-8') as f1, open(file2, 'r', encoding='utf-8') as f2:
        lines1 = f1.readlines()
        lines2 = f2.readlines()
        compare_length = min(len(lines1), len(lines2))

        for i in range (compare_length):
            line1 = lines1[i].rstrip("\n")
            line2 = lines2[i].rstrip("\n")

            if line1 != line2:
                print(f"Difference found at line {i+1}:")
                print(f"File1: {line1}")
                print(f"File2: {line2}")
                sys.exit(1)
    print("Files are identical.")

if __name__ == "__main__":
    # test_sample_in_ball()
    # test_expandA()
    # test_expandS()
    # test_expandMask()
    # compare_output("G:/Y4S1/DATN/PQC_Dilithium/output.txt", "G:/Y4S1/DATN/PQC_Dilithium/fpga/dilithium_test_bench/mem_dump.txt")
    # test_full_scheme(xi, msg, ctx)
    # decompose_lut()
    use_hint_lut()
