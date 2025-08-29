from PQC import *
import sys
from Crypto.Hash import SHAKE256

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
msg = b"Hello Dilithium!"
ctx = b"test_vectors"

def print_hex(label: str, data: bytes):
    length = len(data)
    print(f"{label} ({length} bytes):")
    for i in range(length):
        print(f"{data[i]:02X}", end="")
        if (i + 1) % 128 == 0:
            print()  # xuống dòng sau mỗi 128 byte
    if length % 128 != 0:
        print()  # xuống dòng nếu dòng cuối chưa in


def test(xi, msg, ctx):
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        print_hex("m = : \n", msg)

        pk, sk = ML_DSA_87.KeyGen_internal(xi)
        print_hex("Public key: \n", pk)
        print_hex("Secret key: \n", sk)

        signature = ML_DSA_87.Sign(sk, msg, ctx)
        # signature = ML_DSA_87.Hash_Sign(sk, m, ctx)
        print_hex("Signature: \n", signature)

        valid = ML_DSA_87.Verify(pk, msg, signature, ctx)
        # valid = ML_DSA_87.Hash_Verify(pk, m, signature, ctx)
        res = "Signature valid: " + str(valid)
        print(res)

        sys.stdout = sys.__stdout__ 

def test_round_trip_array():
    values = [1, 42, 255, 1024, 65535]
    bitlen = 32  # cố định độ dài cho mỗi số

    print(f"\n=== Test array: {values} ===")

    # int -> bits (cho cả mảng)
    bits = []
    for v in values:
        bits.extend(int_to_bits(v, bitlen))
    print(f"int_to_bits(array): {bits}")

    # bits -> bytes
    b = bits_to_bytes(bits)
    print(f"bits_to_bytes(...): {list(b)}")

    # bytes -> bits
    bits2 = bytes_to_bits(b)
    print(f"bytes_to_bits(...): {list(bits2)}")

    # bits -> int (chia lại theo từng khối bitlen)
    recovered = []
    for i in range(0, len(bits), bitlen):
        block = bits2[i:i+bitlen]
        recovered.append(bits_to_int(block))
    print(f"bits_to_int(blocks): {recovered}")

    # so sánh
    assert values == recovered, f"Round-trip failed, got {recovered}"

if __name__ == "__main__":
    test(xi, msg, ctx)
    # test_round_trip_array()

