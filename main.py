from PQC import *
import sys

ML_DSA_87 = Dilithium()

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
message = "Hello Dilithium!"
ctx = "test"

def test(xi, message, ctx):
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        m = bytes_to_bits(message.encode("utf-8"))
        print("m = : ", message.encode("utf-8"))

        print("Generate a public - private key pair\n")
        pk, sk = ML_DSA_87.KeyGen_internal(xi)
        print("Public key: ", pk.hex())
        print("Secret key: ", sk.hex())

        print("Sign a message\n")
        signature = ML_DSA_87.Sign(sk, m, ctx.encode("utf-8"))
        # signature = ML_DSA_87.Hash_Sign(sk, m, ctx.encode("utf-8"))
        print("Signature: ", signature.hex())

        print("Verify a signature\n")
        valid = ML_DSA_87.Verify(pk, m, signature, ctx.encode("utf-8"))
        # valid = ML_DSA_87.Hash_Verify(pk, m, signature, ctx.encode("utf-8"))
        res = "Signature valid: " + str(valid)
        print(res)

        sys.stdout = sys.__stdout__ 


if __name__ == "__main__":
    test(xi, message, ctx)

