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
    data_in = b'\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA' * 20 + b'\x44\x33\x33\x22\x22\x11\x11' * 1
    # b'\xAA\xAA\xBB\xBB\xCC\xCC\xDD\xDD' * 16 + b'\x11\x11\x22\x22\x33\x33\x44\x44'
    #// 00,abcd
    #...
    print(data_in.hex())
    shake = SHAKE128.new()
    shake.update(data_in)
    ans = shake.read(32)
    rev_ans = ans[::-1]
    print(rev_ans.hex())

if __name__ == "__main__":
    get_answer()
    # 70041d23693ea1226f614e989d4a31010883346426560ad3e12b83868d1aff1f72f0cb8bb26853b19f0392f89258ed41017126d5d75fca27199ce74c4ed90677b2bd417d8416c3daaaab7d8f8acb8010f92ebac801447a1b5085981e22edc628bf6cc48e2f63a4e07e61a3bf5d974a4e7965a1f53fbd46d158e580854e00464ea301a84380efb01fa0894fea9f71fce432037b75ba6c96943ced9ab12d8a4be9
    # 70041d23693ea1226f614e989d4a31010883346426560ad3e12b83868d1aff1f72f0cb8bb26853b19f0392f89258ed41017126d5d75fca27199ce74c4ed90677b2bd417d8416c3daaaab7d8f8acb8010f92ebac801447a1b5085981e22edc628bf6cc48e2f63a4e07e61a3bf5d974a4e7965a1f53fbd46d158e580854e00464ea301a84380efb01fa0894fea9f71fce432037b75ba6c96943ced9ab12d8a4be9

    #4c5276a8c8566f7c3e8df226fadb179f5cc6e3198500f331137d666ea9fe1612110673604c74972d338b024929052755a5f30667dd124cdd46b06a3d8f8e7fa3092042ae4d1caef70ef50f9f359fd44c82b696e57ff7fb78ebcd05a0d08e2a0722afda55e113ae38208f23b08dc634486ddc1b79f741399232b6e26571447304d1ac8b7f661af380b6cd7111a7fa42d915fdb28e18cca126d1cabfd4059660f2
    #4c5276a8c8566f7c3e8df226fadb179f5cc6e3198500f331137d666ea9fe1612110673604c74972d338b024929052755a5f30667dd124cdd46b06a3d8f8e7fa3092042ae4d1caef70ef50f9f359fd44c82b696e57ff7fb78ebcd05a0d08e2a0722afda55e113ae38208f23b08dc634486ddc1b79f741399232b6e26571447304d1ac8b7f661af380b6cd7111a7fa42d915fdb28e18cca126d1cabfd4059660f2
