from Crypto.Random import get_random_bytes
from Crypto.Hash import SHAKE256, SHAKE128
from SHA3 import *
import sys
import random
import os

NTESTS = 1000
MIN_MSG_LEN = 0
MAX_MSG_LEN = 10000
CONCAT_LOOP = 10
PRINT_TEST = False
 
def test_shake128():
    pass128_test = 0
    print("========== SHAKE128 Tests: =========")
    for _ in range(NTESTS):
        MLEN = random.randint(MIN_MSG_LEN, MAX_MSG_LEN)  
        msg = os.urandom(MLEN)
        if PRINT_TEST:
            print("Message: ", memoryview(msg).hex())
        
        shake128_test = SHAKE_128()
        shake128_true = SHAKE128.new()

        shake128_test.update(msg)
        shake128_true.update(msg)

        test: bytes = b''
        true: bytes = b''
        flag = True
        for i in range(CONCAT_LOOP):
            CONCAT_LEN = random.randint(MIN_MSG_LEN + 1, MAX_MSG_LEN)
            test = shake128_test.read(CONCAT_LEN)
            true = shake128_true.read(CONCAT_LEN)
            if test != true:
                flag = False
            if PRINT_TEST:
                print(f"Loop {i}th with output len({CONCAT_LEN}): " , memoryview(true).hex())
        if flag:
            pass128_test += 1
    print(f"Valid SHAKE128 tests: {pass128_test} / {NTESTS}, pass {pass128_test / NTESTS * 100:.2f}%")

def test_shake256():
    print("========== SHAKE128 Tests: =========")
    pass256_test = 0
    for i in range(NTESTS):
        MLEN = random.randint(MIN_MSG_LEN, MAX_MSG_LEN)  
        msg = os.urandom(MLEN)
        if PRINT_TEST:
            print("Message: ", memoryview(msg).hex())
        
        shake256_test = SHAKE_256()
        shake256_true = SHAKE256.new()

        shake256_test.update(msg)
        shake256_true.update(msg)

        test: bytes = b''
        true: bytes = b''
        flag = True
        for _ in range(CONCAT_LOOP):
            CONCAT_LEN = random.randint(MIN_MSG_LEN + 1, MAX_MSG_LEN)
            test = shake256_test.read(CONCAT_LEN)
            true = shake256_true.read(CONCAT_LEN)
            if test != true:
                flag = False
            if PRINT_TEST:
                print(f"Loop {i}th with output len({CONCAT_LEN}): " , memoryview(true).hex())
        if flag:
            pass256_test += 1
    print(f"Valid SHAKE256 tests: {pass256_test} / {NTESTS}, pass {pass256_test / NTESTS * 100:.2f}%")

def verify_golden_model():
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        test_shake128()
        test_shake256()        
    sys.stdout = sys.__stdout__ 

def get_answer():
    data_in = b'\xef\xcd\xab\x90\x78\x56\x34\x12' * 8 + b'\x01\x00' #34 bytes
    # b'\xAA\xAA\xBB\xBB\xCC\xCC\xDD\xDD' * 16 + b'\x11\x11\x22\x22\x33\x33\x44\x44'
    #// 00,abcd
    #...
    print(data_in.hex())
    shake = SHAKE256.new()
    shake.update(data_in)
    ans = shake.read(8)
    rev_ans = ans[::-1]
    print(rev_ans.hex())

if __name__ == "__main__":
    get_answer()
    #28d26f767f8a8c44928ad88a610b9b67
    #