from typing import List
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHAKE256, SHAKE128

def mod_pm(x: int, m : int) -> int:
    """ Symmetric modulo: x mod^± m
        Returns a remainder r such that: -m//2 <= r <= m//2
    """
    r = x % m
    if r > m // 2:
        r = r - m
    return r

def little_to_big_endian(b: bytes) -> bytes:
    """Converts a little-endian byte string to big-endian."""
    # When using library, the library will handle endian when mapping to state.
    return b[::-1]

def int_to_bits(x: int, bitlen: int) -> List[int]:
    """Algorithm 9: Convert integer x to list of bits (little-endian order)."""
    return [(x >> i) & 1 for i in range(bitlen)]

def bits_to_int(bits: List[int]) -> int:
    """Algorithm 10: Computes the integer value expressed by a bit string using little-endian order."""
    value = 0
    for i, bit in enumerate(bits):
        value |= (bit & 1) << i
    return value

def int_to_bytes(x: int, length: int) -> bytes:
    """Algorithm 11: Convert integer x to bytes."""
    return x.to_bytes(length, 'little')

def bits_to_bytes(bits: List[int]) -> bytes:
    """Algorithm 12: Converts a bit string into a byte string using little-endian order."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                bit = bits[i + j] & 1
                byte |= bit << j
        out.append(byte)
    return bytes(out)

def bytes_to_bits(b: bytes) -> List[int]:
    """Algorithm 13: Converts a byte string into a bit string using little-endian order."""
    bits: List[int] = []
    for byte in b:
        for j in range(8):
            bits.append((byte >> j) & 1)
    return bits

def bitlen(x: int) -> int:
    if x == 0:
        return 1
    return x.bit_length()

def H(str: bytes, outlen: int) -> bytes:
    """ 
        Input: str is a byte string of any length, outlen is the desired output length in bytes
        Output: A byte string of length outlen
    """
    shake = SHAKE256.new()
    shake.update(str)
    return shake.read(outlen)

def G(str: bytes, outlen: int) -> bytes:
    """ 
        Input: str is a byte string of any length, outlen is the desired output length in bytes
        Output: A byte string of length outlen
    """
    shake = SHAKE128.new()
    shake.update(str)
    return shake.read(outlen)

zetas = [   0,          4808194,    3765607,    3761513,    5178923,    5496691,    5234739,    5178987,
            7778734,    3542485,    2682288,    2129892,    3764867,    7375178,    557458,     7159240,
            5010068,    4317364,    2663378,    6705802,    4855975,    7946292,    676590,     7044481,
            5152541,    1714295,    2453983,    1460718,    7737789,    4795319,    2815639,    2283733,
            3602218,    3182878,    2740543,    4793971,    5269599,    2101410,    3704823,    1159875,
            394148,     928749,     1095468,    4874037,    2071829,    4361428,    3241972,    2156050,
            3415069,    1759347,    7562881,    4805951,    3756790,    6444618,    6663429,    4430364,
            5483103,    3192354,    556856,     3870317,    2917338,    1853806,    3345963,    1858416,
            3073009,    1277625,    5744944,    3852015,    4183372,    5157610,    5258977,    8106357,
            2508980,    2028118,    1937570,    4564692,    2811291,    5396636,    7270901,    4158088,
            1528066,    482649,     1148858,    5418153,    7814814,    169688,     2462444,    5046034,
            4213992,    4892034,    1987814,    5183169,    1736313,    235407,     5130263,    3258457,
            5801164,    1787943,    5989328,    6125690,    3482206,    4197502,    7080401,    6018354,
            7062739,    2461387,    3035980,    621164,     3901472,    7153756,    2925816,    3374250,
            1356448,    5604662,    2683270,    5601629,    4912752,    2312838,    7727142,    7921254,
            348812,     8052569,    1011223,    6026202,    4561790,    6458164,    6143691,    1744507,
            1753,       6444997,    5720892,    6924527,    2660408,    6600190,    8321269,    2772600,
            1182243,    87208,      636927,     4415111,    4423672,    6084020,    5095502,    4663471,
            8352605,    822541,     1009365,    5926272,    6400920,    1596822,    4423473,    4620952,
            6695264,    4969849,    2678278,    4611469,    4829411,    635956,     8129971,    5925040,
            4234153,    6607829,    2192938,    6653329,    2387513,    4768667,    8111961,    5199961,
            3747250,    2296099,    1239911,    4541938,    3195676,    2642980,    1254190,    8368000,
            2998219,    141835,     8291116,    2513018,    7025525,    613238,     7070156,    6161950,
            7921677,    6458423,    4040196,    4908348,    2039144,    6500539,    7561656,    6201452,
            6757063,    2105286,    6006015,    6346610,    586241,     7200804,    527981,     5637006,
            6903432,    1994046,    2491325,    6987258,    507927,     7192532,    7655613,    6545891,
            5346675,    8041997,    2647994,    3009748,    5767564,    4148469,    749577,     4357667,
            3980599,    2569011,    6764887,    1723229,    1665318,    2028038,    1163598,    5011144,
            3994671,    8368538,    7009900,    3020393,    3363542,    214880,     545376,     7609976,
            3105558,    7277073,    508145,     7826699,    860144,     3430436,    140244,     6866265,
            6195333,    3123762,    2358373,    6187330,    5365997,    6663603,    2926054,    7987710,
            8077412,    3531229,    4405932,    4606686,    1900052,    7598542,    1054478,    7648983 ]

class Dilithium:
    """ Parameters for Dilithium (Default: ML-DSA-87):
        q = 2^23 - 2^13 + 1     a prime, the modulus used in the polynomial ring Z_q
        n = 256                 the polynomial degree in the ring R_q = Z_q[x]/(x^n + 1)
        (k, l) = (8, 7)         the matrix dimensions in the scheme
        k = 8                   number of components in the secret vector s2    
        l = 7                   number of components in the secret vector s1    
        eta = 2                 the bound for coefficients of secret vectors s1, s2
        d = 13                  number of bits used for rounding during compression of polynomial coefficients.
        gamma1 = 2^19           Upper bound for vectors z in the signature.
        tau = 60                number of nonzero coefficients in the challenge polynomial c
        beta = 120              threshold for acceptance/rejection during signature verification.  
        gamma2 = (q - 1)/32     controls the level of noise in the signature.
        lambda_ = 256           the security level in bits
        omega = 75              number of nonzero coefficients in the hint polynomial h
    """
    """ Others parameters:
        zeta = 1753              512-th primitive root of unity in Z_q
        zetainv = 587            zeta^-1 mod q
    """
    def __init__(self, q = 2**23 - 2**13 + 1, n = 256, 
                       k = 8, l = 7, eta = 2, d = 13, 
                       gamma1 = 2**19, tau = 60, beta = 120,
                       gamma2 = (2**23 - 2**13 + 1 - 1)//32,
                       lambda_ = 256, omega = 75, zeta = 1753):
        self.q = q
        self.n = n
        self.k = k
        self.l = l
        self.eta = eta
        self.d = d
        self.gamma1 = gamma1
        self.tau = tau
        self.beta = beta
        self.gamma2 = gamma2
        self.lambda_ = lambda_
        self.omega = omega
        self.zeta = zeta
        self.zetainv = pow(zeta, q - 2, q)  # zeta^-1 mod q

    def infinityNorm(self, obj) -> int:
        """Compute infinity norm"""
        if isinstance(obj, int):
            return abs(mod_pm(obj, self.q))
        if all(isinstance(x, int) for x in obj):
            return max(abs(mod_pm(x, self.q)) for x in obj)
        if all(isinstance(x, list) and all(isinstance(c, int) for c in x) for x in obj):
            return max(abs(mod_pm(c, self.q)) for x in obj for c in x)
        if all(isinstance(x, list) for x in obj):
            return max(self.infinityNorm(row) for row in obj)
        raise ValueError("Unsupported type for infinityNorm")
    
    def KeyGen(self) -> tuple[bytes, bytes]:
        """ 
            Generate a public - private key pair
            Reference: Algorithm 1: Key generation, FIPS 204 page 17, slide 27
            Input: None
            Output: Public key pk, private key sk
        """
        xi = get_random_bytes(32)  # xi is a 32-byte random string
        if not xi or len(xi) != 32:
            raise ValueError("xi is NULL or not 32 bytes")
        return self.KeyGen_internal(xi)
    
    def Sign(self, sk: bytes, m: bytes, ctx: bytes) -> bytes:   
        """
            Generates an ML-DSA signature
            Reference: Algorithm 2, FIPS 204 page 18, slide 28
            Input:  private key sk, message m, context ctx
                    m is a bit string, this function represents it as byte string
            Output: signature sigma (bytes)
        """
        if len(ctx) > 255:
            raise ValueError("context length exceeds 255 bytes")
        rnd = b'\x00' * 32      #either use random seed, for the optional deterministic variant, substitute rnd = {0}^32
        if not rnd:
            raise ValueError("rnd is NULL")
        M_ = (int_to_bytes(0, 1) + int_to_bytes(len(ctx), 1) + ctx) + m  
        sigma = self.Sign_internal(sk, M_, rnd)
        return sigma

    def Verify(self, pk: bytes, M: bytes, sigma: bytes, ctx: bytes) -> bool:
        """
            Verifies a signature sigma for a message M
            Reference: Algorithm 3, FIPS 204 page 18, slide 28
            Input:  public key pk (length of 32 + 32*k*bitlen(q-1)-d), message m, context ctx, signature sigma
            Output: True if the signature is valid, False otherwise
        """
        if len(ctx) > 255:
            raise ValueError("context length exceeds 255 bytes")
        M_ = (int_to_bytes(0, 1) + int_to_bytes(len(ctx), 1) + ctx) + M
        return self.Verify_internal(pk, M_, sigma)

    def Hash_Sign(self, sk: bytes, M: bytes, ctx: bytes) -> bytes:
        """
            Generate a “pre-hash” ML-DSA signature
            Reference: Algorithm 4, FIPS 204 page 20, slide 30
            Input:  private key sk (length of 32 + 32 + 64 + 32*((l+k)*bitlen(2*eta) + d*k)), 
                    message M, context ctx (<= 255 bytes) 
                    ##pre-hash function SHA-256##  
            Output: signature sigma (length of lambda/4 + 32*l*(1+bitlen(gamma1-1)) + omega + k)
        """
        if len(ctx) > 255:
            raise ValueError("context length exceeds 255 bytes")
        rnd = b'\x00' * 32      #either use random seed, for the optional deterministic variant, substitute rnd = {0}^32
        if not rnd:
            raise ValueError("rnd is NULL")
        OID = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) #ODI_SHA-256 = 2.16.840.1.101.3.4.2.1
        PH_M = hashlib.sha256(M).digest()
        M_ = (int_to_bytes(1, 1) + int_to_bytes(len(ctx), 1) + ctx + OID + PH_M)
        sigma = self.Sign_internal(sk, M_, rnd)
        return sigma

    def Hash_Verify(self, pk: bytes, M: bytes, sigma: bytes, ctx: bytes) -> bool:
        """
            Verifies a pre-hash HashML-DSA signature
            Reference: Algorithm 5, FIPS 204 page 21, slide 31
            Input:  public key pk (length of 32 + 32*k*bitlen(q-1)-d), 
                    message m, context ctx, signature sigma
                    ##pre-hash function SHA-256##  
            Output: True if the signature is valid, False otherwise
        """
        if len(ctx) > 255:
            raise ValueError("context length exceeds 255 bytes")
        OID = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) #ODI_SHA-256 = 2.16.840.
        PH_M = hashlib.sha256(M).digest()
        M_ = (int_to_bytes(1, 1) + int_to_bytes(len(ctx), 1) + ctx + OID + PH_M)
        return self.Verify_internal(pk, M_, sigma)
    
    def KeyGen_internal(self, xi: bytes) -> tuple[bytes, bytes]:
        """ 
            Generate a public - private key pair from a seed
            Reference: Algorithm 6: Key generation, FIPS 204 page 23, slide 33
            Input: xi is a 32-byte random string
            Output: Public key pk, private key sk
        """
        concat = xi + int_to_bytes(self.k, 1) + int_to_bytes(self.l, 1)
        hash = H(concat, 128)
        rho = hash[0:32]
        rho_prime = hash[32:96]
        K = hash[96:128]

        A = self.ExpandA(rho)      
        s1, s2 = self.ExpandS(rho_prime)

        s1_ntt = [self.NTT(poly) for poly in s1]
        A_mul_s1_NTT = self.MatrixVectorNTT(A, s1_ntt)
        A_mul_s1 = [self.NTT_inv(poly) for poly in A_mul_s1_NTT]
        t = [[] for i in range(self.k)]
        for i in range(self.k):
            t[i] = [(A_mul_s1[i][j] + s2[i][j]) % self.q for j in range(self.n)]
        
        t1 = [[0]*self.n for _ in range(self.k)]
        t0 = [[0]*self.n for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.n):
                t1_ij, t0_ij = self.Power2Round(t[i][j])
                t1[i][j] = t1_ij
                t0[i][j] = t0_ij
                
        pk = self.pkEncode(rho, t1)
        tr = H(pk, 64)
        sk = self.skEncode(rho, K, tr, s1, s2, t0)
        return pk, sk 

    def Sign_internal(self, sk: bytes, M_: bytes, rnd: bytes) -> bytes:
        """
            Deterministic algorithm to generate a signature for a formatted message M_
            Reference: Algorithm 7, FIPS 204 page 25, slide 35
            Input: private key sk, formatted message M_, random seed rnd
            Output: signature si
        """
        rho, K, tr, s1, s2, t0 = self.skDecode(sk)
        s1_ntt = [self.NTT(poly) for poly in s1]
        s2_ntt = [self.NTT(poly) for poly in s2]
        t0_ntt = [self.NTT(poly) for poly in t0]
        A_ntt = self.ExpandA(rho)
        mu = H(tr + M_, 64)
        rho__ = H(K + rnd + mu, 64)

        kappa = 0
        z = [[0]*self.n for _ in range(self.l)]
        h = [0] * 256
        _c = b''
        h = []
        found = False

        while found == False:
            y = self.ExpandMask(rho__, kappa)
            y_ntt = [self.NTT(poly) for poly in y]
            A_mul_y_NTT = self.MatrixVectorNTT(A_ntt, y_ntt)
            w = [self.NTT_inv(poly) for poly in A_mul_y_NTT]
            w1 = [[self.HighBits(w[i][j]) for j in range(self.n)] for i in range(self.k)] # w1 = HighBits(w) in R_q^k
            
            _c = H(mu + self.w1Encode(w1), self.lambda_ // 4) # c~
            c = self.SampleInBall(_c)
            c_ntt = self.NTT(c) # c in T_q, c^
            cs1_ntt = self.ScalarVectorNTT(c_ntt, s1_ntt) # c * s1 in T_q^l
            inner_product_cs1 = [self.NTT_inv(poly) for poly in cs1_ntt] # c * s1 in R_q^l
            cs2_ntt = self.ScalarVectorNTT(c_ntt, s2_ntt) # c * s2 in T_q^k
            inner_product_cs2 = [self.NTT_inv(poly) for poly in cs2_ntt] # c * s2 in R_q^k
            z = self.AddVectorNTT(y, inner_product_cs1) # z = y + c * s1 in R_q^l
            
            w_sub_cs2 = self.AddVectorNTT(w, [[-inner_product_cs2[i][j] for j in range(self.n)] for i in range(self.k)]) # w - c * s2 in R_q^k
            r0 = [[self.LowBits(w_sub_cs2[i][j]) for j in range(self.n)] for i in range(self.k)] # r0 = LowBits(w - c * s2) in R_q^k

            if (self.infinityNorm(z) >= (self.gamma1 - self.beta)) or (self.infinityNorm(r0) >= (self.gamma2 - self.beta)):
                kappa = kappa + self.l
                continue
            else:
                c_mul_t0_ntt = self.ScalarVectorNTT(c_ntt, t0_ntt) # c * t0 in T_q^k
                inner_product_ct0 = [self.NTT_inv(poly) for poly in c_mul_t0_ntt] # c * t0 in R_q^k
                h = [[self.MakeHint(-inner_product_ct0[i][j], w[i][j] - inner_product_cs2[i][j] + inner_product_ct0[i][j])
                      for j in range(self.n)] for i in range(self.k)] # h = MakeHint(-c * t0, w - c * s2 + c * t0) in {0, 1}^n
                if (self.infinityNorm(inner_product_ct0) >= self.gamma2) or (sum(sum(row) for row in h) > self.omega):
                    kappa = kappa + self.l
                    continue
                else:
                    found = True
        z_mod_pm = [[mod_pm(z[i][j], self.q) for j in range(self.n)] for i in range(self.l)]
        sigma = self.SigEncode(_c, z_mod_pm, h)
        return sigma

    def Verify_internal(self, pk: bytes, M_: bytes, sigma: bytes) -> bool:
        """
            Internal function to verify a signature sigma for a formatted message M'
            Reference: Algorithm 8: Signature verification, FIPS 204 page 27, slide 37
            Input:  Public key pk (length of 32 + 32*k*(bitlen(q-1)-d) bytes), formatted message M_, 
                    signature sigma (length of lambda/4 + 32*l*(1+bitlen(gamma1-1)) + omega + k)
            Output: True if the signature is valid, False otherwise
        """
        rho, t1 = self.pkDecode(pk)
        _c, z, h = self.SigDecode(sigma)    # c~, z, h
        if h == [[0]*self.n for _ in range(self.k)]:
            return False
        A_ = self.ExpandA(rho)  # A^ in T_q^{k x l} 
        tr = H(pk, 64)
        mu = H(tr + M_, 64)
        c = self.SampleInBall(_c)

        # w'_Approx = NTT^{−1}(A^ * NTT(z) − NTT(c) * NTT(t1 * 2d)) => w' = Az - ct1 * 2^d
        z_ntt = [self.NTT(poly) for poly in z]
        c_ntt = self.NTT(c)
        t1_mul_2_power_d = [[t1[i][j] * (2 ** self.d) % self.q for j in range(256)] for i in range(self.k)]
        t1_mul_2_power_d_ntt = [self.NTT(poly) for poly in t1_mul_2_power_d]
        A_mul_z_ntt = self.MatrixVectorNTT(A_, z_ntt) 
        ct1_mul_2_power_d_ntt = self.ScalarVectorNTT(c_ntt, t1_mul_2_power_d_ntt)
        w__Approx_ntt = [[ (A_mul_z_ntt[i][j] - ct1_mul_2_power_d_ntt[i][j]) % self.q for j in range (256) ] for i in range (self.k) ]
        w__Approx = [self.NTT_inv(poly) for poly in w__Approx_ntt]
        w_1 = [[self.UseHint(h[i][j], w__Approx[i][j]) for j in range(256)] for i in range(self.k)] # w1' = UseHint(h, w'_Approx)
        _c_ = H(mu + self.w1Encode(w_1), self.lambda_ // 4) # c~' = H(mu||w1Encode(w'1), lambda/4)
        return (self.infinityNorm(z) < self.gamma1 - self.beta) and (_c == _c_)

    """
        Computes a base-2 representation of x mod 2^a using little-endian order.
        Reference: Algorithm 9: IntegerToBits(x, a), FIPS 204 page 28, slide 38
        Input:  Integer x and a
        Output: A list of bits representing x mod 2^a
        This function is defined outside Dilithium class
        => def int_to_bits(x: int, bitlen: int) -> List[int]:
    """

    """
        Computes the integer value expressed by a bit string using little-endian order
        Reference: Algorithm 10: BitsToInteger(y, a), FIPS 204 page 28, slide 38
        Input: A positive integer a and a bit string y of length a.
        Output: A nonnegative integer x.
        This function is defined outside Dilithium class
        => def bits_to_int(bits: List[int]) -> int:
    """

    """
        Computes a base-256 representation of x mod 256^a using little-endian order.
        Reference: Algorithm 11: IntegerToBytes(x, a), FIPS 204 page 28, slide 38
        Input:  Integer x and a
        Output: A byte string y of length a
        This function is defined outside Dilithium class
        => def int_to_bytes(x: int, length: int) -> bytes:
    """

    """
        Converts a bit string into a byte string using little-endian order.
        Reference: Algorithm 12: BitsToBytes(y), FIPS 204 page 29, slide 39
        Input:  A bit string y of length a
        Output: A byte string of length a/8
        This function is defined outside Dilithium class
        => def bits_to_bytes(bits: List[int]) -> bytes:
    """

    """
        Converts a byte string into a bit string using little-endian order.
        Reference: Algorithm 13: BytesToBits(z), FIPS 204 page 29, slide 39
        This function is defined outside Dilithium class
        => def bytes_to_bits(b: bytes) -> bytes:
    """

    def CoeffFromThreeBytes(self, b0: int, b1: int, b2: int) -> int:
        """
            Generates an element of {0, 1, 2, ..., q-1} from 3 bytes
            Reference: Algorithm 14: Coefficient generation from three bytes, FIPS 204 page 29, slide 39
            Intput: Three bytes b0, b1, b2
            Output: An integer in {0, 1, 2, ..., q-1} or NULL
        """
        b2_ = b2
        if b2_ > 127:
            b2_ = b2_ - 128
        z = (2 ** 16) * b2_ + (2 ** 8) * b1 + b0
        if z < self.q:
            return z
        else:
            return -1

    def CoeffFromHalfByte(self, b: int) -> int:
        """
            Generates an element of {-eta, ..., eta} from a half byte
            Reference: Algorithm 15: Coefficient generation from a half byte, FIPS 204 page 30, slide 40
            Input: A half byte b (0 <= b < 16)
            Output: An integer in {-eta, ..., eta} or NULL
        """
        if self.eta == 2 and b < 15:
            return 2 - (b % 5)
        else:
            if self.eta == 4 and b < 9:
                return 4 - b
            else:
                return -1
        
    @staticmethod
    def SimpleBitPack(w: List[int], b: int) -> bytes:
        """
            Encode a polynomial w into a byte string
            Reference: Algorithm 16: Simple bit packing, FIPS 204 page 30, slide 40
            Input: integer b and w is a polynomial in R_q with coefficients in [0, b]
            Output: A byte string of length 32 * bitlen(b)
        """ 
        z: List[int] = []
        length = bitlen(b)
        for i in range(0, 256):
            z.extend(int_to_bits(w[i], length))  # append b bits of w[i]
        return bits_to_bytes(z)
    
    @staticmethod
    def BitPack(w: List[int], a: int, b: int) -> bytes:
        """
            Encode a polynomial w into a byte string
            Reference: Algorithm 17: Bit packing, FIPS 204 page 30, slide 40
            Input:  a, b in integer 
                    w is a polynomial in R_q with coefficients in [-a, b]
            Output: A byte string of length 32 * bitlen(a + b)
        """ 
        z: List[int] = []
        for i in range(0, 256):
            z.extend(int_to_bits(b - w[i], bitlen(a + b)))
        return bits_to_bytes(z)

    def SimpleBitUnpack(self, v: bytes, b: int) -> List[int]:
        """
            Reverses the procedure of SimpleBitPack
            Reference: Algorithm 18: Simple bit unpacking, FIPS 204 page 31, slide 41
            Input:  integer b and v is a byte string of length 32 * bitlen(b)
            Output: A polynomial w in R_q with coefficients in [0, 2^c - 1] where c = bitlen(b)
                    When b + 1 is a power of 2, the coefficients are in [0, b].
        """
        c = bitlen(b)
        z = bytes_to_bits(v)
        w: List[int] = []
        for i in range(0, 256):
            wi = z[i * c : (i + 1) * c]
            val = bits_to_int(wi)
            w.append(val)
        return w

    def BitUnpack(self, v: bytes, a: int, b: int) -> List[int]:
        """
            Reverses the procedure of BitPack
            Reference: Algorithm 19: Bit unpacking, FIPS 204 page 31, slide 41
            Input:  a, b in integer 
                    v is a byte string of length 32 * bitlen(a + b)
            Output: A polynomial w in R_q with coefficients in [b - 2^c + 1, b] where c = bitlen(a + b)
                    When a + b + 1 is a power of 2, the coefficients are in [-a, b] 
        """ 
        c = bitlen(a + b)
        z = bytes_to_bits(v) # bit array LSB first
        w: List[int] = []
        for i in range(0, 256):
            coeff_bits = z[i * c : (i + 1) * c]
            val = bits_to_int(coeff_bits)
            wi = b - val
            w.append(wi)
        return w

    def HintBitPack(self, h: List[List[int]]) -> bytes:
        """
            Encodes a polynomial vector h with binary coefficients into a byte string. (h is represented in 2D array)
            Reference: Algorithm 20: Hint bit packing, FIPS 204 page 32, slide 42
            Input: h (list of k polynomials in {0, 1}^n) with at most omega nonzero coefficients (represented in 2D array)
            Output: A byte string of length (omega + k) bytes
        """
        y = bytearray(self.omega + self.k)  # initialize output bytearray
        idx = 0
        for i in range(self.k):
            for j in range(0, 256):
                if h[i][j] != 0:
                    y[idx] = j
                    idx += 1
            y[self.omega + i] = idx
        return bytes(y)
    
    def HintBitUnpack(self, y: bytes) -> List[List[int]]:
        """
            Reverses the procedure HintBitPack
            Reference: Algorithm 21: Hint bit unpacking, FIPS 204 page 32, slide 42
            Input: y is a byte string of length (omega + k) bytes 
            Output: polynomial vector h in R_2^k or NULL (represented in 2D array) 
        """
        h = [[0]*self.n for _ in range(self.k)]
        idx = 0
        for i in range(self.k):
            if y[self.omega + i] < idx or y[self.omega + i] > self.omega:
                return [[-1]*self.n for _ in range(self.k)]
            first = idx
            while idx < y[self.omega + i]:
                if idx > first:
                    if y[idx - 1] >= y[idx]:
                        return [[-1]*self.n for _ in range(self.k)]
                h[i][y[idx]] = 1
                idx += 1
        for i in range(idx, self.omega):
            if y[i] != 0:
                return [[-1]*self.n for _ in range(self.k)]
        return h
            

    def pkEncode(self, rho: bytes, t1: List[List[int]]) -> bytes:
        """
            Encode a public key for ML-DSA into a byte string
            Reference: Algorithm 22: Public key encoding, FIPS 204 page 33, slide 43
            Input: rho (32 bytes), t1 (list of k polynomials in R_q^k) with coefficients in [0, 2^(23-1-d)-1])
            Output: public key pk (a byte string of length 32 + 32*k*(bitlen(q-1)-d) bytes)
        """
        pk = rho
        for i in range(self.k):
            pk = pk + Dilithium.SimpleBitPack(t1[i], 2 ** (bitlen(self.q - 1) - self.d)  - 1)
        return pk
    
    def pkDecode(self, pk: bytes) -> tuple[bytes, List[List[int]]]:
        """
            Reverses the procedure pkEncode
            Reference: Algorithm 23: Public key decoding, FIPS 204 page 33, slide 43
            Input: public key pk (a byte string of length 32 + 32*k*(bitlen(q-1)-d) bytes)
            Output: rho (32 bytes), t1 (list of k polynomials in R_q^k) with coefficients in [0, 2^(bitlen(q-1)-d)-1])
        """
        rho = pk[0:32]
        offset = 32
        t1 = []
        for i in range(self.k):
            size = 32 * (bitlen(self.q - 1) - self.d)
            zi = pk[offset : offset + size]; offset += size
            poly = self.SimpleBitUnpack(zi, 2 ** (bitlen(self.q - 1) - self.d) - 1)
            t1.append(poly)
        return rho, t1
    
    def skEncode(self, rho: bytes, K: bytes, tr: bytes, s1: List[List[int]], s2: List[List[int]], t0: List[List[int]]) -> bytes:
        """
            Encodes a secret key for ML-DSA into a byte string.
            Reference: Algorithm 24: Secret key encoding, FIPS 204 page 34, slide 44
            Input:  rho (32 bytes), K (32 bytes), tr (64 bytes), 
                    s1 (list of l polynomials in R_q^l) with coefficients in [-eta, eta], 
                    s2 (list of k polynomials in R_q^k) with coefficients in [-eta, eta], 
                    t0 (list of k polynomials in R_q^k) with coefficients in [-2^(d)-1, 2^(d)-1]
            Output: secret key sk (a byte string of length 32 + 32 + 64 + 32*((k+l)*bitlen(2*eta) + d*k) bytes)    
        """
        sk = rho + K + tr
        for i in range(self.l):
            sk += Dilithium.BitPack(s1[i], self.eta, self.eta)
        for i in range(self.k):
            sk += Dilithium.BitPack(s2[i], self.eta, self.eta)
        for i in range(self.k):
            sk += Dilithium.BitPack(t0[i], 2 ** (self.d - 1) - 1, 2 ** (self.d - 1))
        return sk

    def skDecode(self, sk: bytes) -> tuple[bytes, bytes, bytes, List[List[int]], List[List[int]], List[List[int]]]:
        """
            Reverses the procedure skEncode
            Reference: Algorithm 25: Secret key decoding, FIPS 204 page 34, slide 44
            Input:  private key sk (a byte string of length 32 + 32 + 64 + 32*((k+l)*bitlen(2*eta) + d*k) bytes)    
            Output: rho (32 bytes), K (32 bytes), tr (64 bytes), 
                    s1 (list of l polynomials in R_q^l) with coefficients in [-eta, eta], 
                    s2 (list of k polynomials in R_q^k) with coefficients in [-eta, eta], 
                    t0 (list of k polynomials in R_q^k) with coefficients in [-2^(d-1) + 1, 2^(d-1)]
        """
        rho = sk[0:32]
        K = sk[32:64]
        tr = sk[64:128]
        offset = 128

        s1 = []
        for i in range(self.l):
            size = 32 * bitlen(2 * self.eta)
            y = sk[offset : offset + size]; offset += size
            poly = self.BitUnpack(y, self.eta, self.eta)
            s1.append(poly)

        s2 = []
        for i in range(self.k):
            size = 32 * bitlen(2 * self.eta)
            z = sk[offset : offset + size]; offset += size
            poly = self.BitUnpack(z, self.eta, self.eta)
            s2.append(poly)

        t0 = []
        for i in range(self.k):
            size = 32 * self.d
            w = sk[offset : offset + size]; offset += size
            poly = self.BitUnpack(w, 2 ** (self.d - 1) - 1, 2 ** (self.d - 1))
            t0.append(poly)
        return rho, K, tr, s1, s2, t0
    
    def SigEncode(self, _c: bytes, z: List[List[int]], h: List[List[int]]) -> bytes:
        """
            Encode a signature for ML-DSA into a byte string
            Reference: Algorithm 26: Signature encoding, FIPS 204 page 35, slide 45
            Input: _c (lambda/4 bytes), z (list of l polynomials in R_q^l) with coefficients in [-gamma1 + 1, gamma1], 
                   h (list of k polynomials in {0, 1}^n) with at most omega nonzero coefficients (represented in 2D array)
            Output: signature sigma (a byte string of length (lambda/4 + 32*l*(1 + bitlen(gamma1-1)) + omega + kappa) bytes)
        """
        # if not _c or len(_c) != self.lambda_ // 4:
        #     raise ValueError("_c is NULL or not lambda/4 bytes")
        sigma = _c
        for i in range(self.l):
            sigma += Dilithium.BitPack(z[i], self.gamma1 - 1, self.gamma1)
        sigma += self.HintBitPack(h)
        return sigma
    
    def SigDecode(self, sigma: bytes) -> tuple[bytes, List[List[int]], List[List[int]]]:
        """
            Reverses the procedure SigEncode
            Reference: Algorithm 27: Signature decoding, FIPS 204 page 35, slide 45
            Input: signature sigma (a byte string of length (lambda/4 + 32*l*(1 + bitlen(gamma1-1)) + omega + kappa) bytes)
            Output: _c (lambda/4 bytes), z (list of l polynomials in R_q^l) with coefficients in [-gamma1 + 1, gamma1], 
                    h (list of k polynomials in {0, 1}^n) with at most omega nonzero coefficients (represented in 2D array)
        """
        _c = sigma[0 : self.lambda_ // 4]
        offset = self.lambda_ // 4
        z = []
        for i in range(self.l):
            size = 32 * (1 + bitlen(self.gamma1 - 1))
            zi = sigma[offset : offset + size]; offset += size
            poly = self.BitUnpack(zi, self.gamma1 - 1, self.gamma1)
            z.append(poly)
        y = sigma[offset : ]
        h = self.HintBitUnpack(y)
        return _c, z, h


    def w1Encode(self, w1: List[List[int]]) -> bytes:
        """
            Encode a polynomial w1 into a byte string
            Reference: Algorithm 28: Encoding w1, FIPS 204 page 35, slide 45
            Input: w1 (list of k polynomials in R_q^k) with coefficients in [0, (q-1)/(2 * gamma2) - 1]
            Output: A byte string of length  32*k*bitlen((q-1)/(2*gamma2)-1) bytes
        """
        _w1 = b''   #w1~
        for i in range(self.k):
            _w1 = _w1 + Dilithium.SimpleBitPack(w1[i], (self.q - 1)//(2 * self.gamma2) - 1)
        return _w1
    
    def SampleInBall(self, rho: bytes) -> List[int]:
        """
            Samples a polynomial c in R_q with coefficients in {-1, 0, 1} and Hamming weight tau <= 64
            Reference: Algorithm 29: Sampling the challenge polynomial c, FIPS 204 page 36, slide 46
            Input: rho (typically lambda/4 bytes from H(mu || w1Encode(w1)) in Sign)
            Output: An polynomial c in R_q (list of 256 coefficients in R_q)
        """
        if not rho:
            raise ValueError("c~ is NULL")
        # if len(rho) * 8 < self.tau * (self.tau + 1).bit_length():
        #     raise ValueError("length of _c is too small")
        c = [0] * 256
        ctx = SHAKE256.new()    # H.Init
        ctx.update(rho)         # H.Absorb(ctx, rho)
        s = ctx.read(8)         # H.Squeeze(ctx, 8)
        h = bytes_to_bits(s)    # bit array LSB first, recheck that h has to be a bit string of length 64
        for i in range(256 - self.tau, 256):
            j = ctx.read(1)     # H.Squeeze(ctx, 1)
            while j[0] > i:
                j = ctx.read(1) # H.Squeeze(ctx, 1)
            c[i] = c[j[0]]
            c[j[0]] = (-1) ** h[i + self.tau - 256]
        return c
    
    def RejNTTPoly(self, rho: bytes) -> List[int]:
        """
            Samples a polynomial in T_q
            Reference: Algorithm 30: Rejection sampling, FIPS 204 page 37, slide 47
            Input: seed (typically 34 bytes from rho || s || r in ExpandA)
            Output: An element in T_q (list of 256 coefficients in T_q)
        """
        if not rho:
            raise ValueError("rho is NULL")
        ans = [0] * 256
        j = 0
        ctx = SHAKE128.new()    #G.Init
        ctx.update(rho)         #G.Absorb(ctx, rho)
        while j < 256:
            s = ctx.read(3)     #G.Squeeze(ctx, 3)
            ans[j] = self.CoeffFromThreeBytes(s[0], s[1], s[2])
            if ans[j] != -1:
                j = j + 1
        return ans
        
    def RejBoundedPoly(self, seed: bytes) -> List[int]:
        """
            Samples a polynomial in R_q with coefficients in [-eta, eta]
            Reference: Algorithm 31: Rejection sampling, FIPS 204 page 37, slide 47
            Input: seed (typically 66 bytes from rho' || 2 bytes in ExpandS)
            Output: An element in R_q with coefficients in [-eta, eta] (list of 256 coefficients in R_q)
        """
        if not seed:
            raise ValueError("seed is NULL")
        ans = [0] * 256
        j = 0
        ctx = SHAKE256.new()    #H.Init
        ctx.update(seed)        #H.Absorb(ctx, seed)
        while j < 256:
            z = ctx.read(1)     #H.Squeeze(ctx, 1)
            z0 = self.CoeffFromHalfByte(z[0] % 16)
            z1 = self.CoeffFromHalfByte(z[0] // 16)
            if z0 != -1:
                ans[j] = z0
                j = j + 1
            if z1 != -1 and j < 256:
                ans[j] = z1
                j = j + 1
        return ans

    def ExpandA(self, rho: bytes) -> List[List[List[int]]]:
        """ 
            Samples a {k x l} matrix A in T_q from a seed rho
            Reference: Algorithm 32: FIPS 204 page 38, slide 48
            Input: rho is a 32-byte seed
            Output: Matrix A in T_q^{k x l}
                    Each entry is a polynomial (list of 256 coefficients mod q)
        """
        if not rho or len(rho) != 32:
            raise ValueError("rho is NULL or not 32 bytes")
        A = [[ [0]*256 for _ in range(self.l)] for _ in range(self.k)]
        for r in range(self.k):
            for s in range(self.l):
                rho_prime = rho + int_to_bytes(s, 1) + int_to_bytes(r, 1)
                A[r][s] = self.RejNTTPoly(rho_prime)
        return A
    
    def  ExpandS(self, rho_prime: bytes) -> tuple[List[List[int]], List[List[int]]]:
        """ 
            Samples vector s1 in R_q^l and s2 in R_q^k with coefficients in [-eta, eta]
            Reference: Algorithm 33: Sampling the secret vectors s1 and s2, FIPS 204 page 38, slide 48
            Input: rho_prime is a 64-byte seed
            Output: Vector s1 and s2 of polynomials in R_q
                    Each entry is a polynomial (list of 256 coefficients mod q)
        """
        if not rho_prime or len(rho_prime) != 64:
            raise ValueError("rho_prime is NULL or not 64 bytes")
        s1 = [[0]*256 for _ in range(self.l)]
        s2 = [[0]*256 for _ in range(self.k)]
        for r in range(0, self.l):
            seed = rho_prime + int_to_bytes(r, 2)
            s1[r] = self.RejBoundedPoly(seed)
        for r in range(0, self.k):
            seed = rho_prime + int_to_bytes(r + self.l, 2)
            s2[r] = self.RejBoundedPoly(seed)
        return s1, s2 
    
    def ExpandMask(self, rho: bytes, mu: int) -> List[List[int]]:
        """ 
            Samples vector y in R_q^l with coefficients in [-gamma1 + 1, gamma1]
            Reference: Algorithm 34: Sampling the vector y, FIPS 204 page 38, slide 48
            Input: rho is a 64-byte seed, mu is a non-negative integer
            Output: Vector y of polynomials in R_q
                    Each entry is a polynomial (list of 256 coefficients mod q)
        """
        if not rho or len(rho) != 64:
            raise ValueError("rho__ is NULL or not 64 bytes")
        c = 1 + bitlen(self.gamma1 - 1)
        y = [[0]*256 for _ in range(self.l)]
        for r in range(self.l):
            rho_ = rho + int_to_bytes(mu + r, 2)
            v = H(rho_, 32 * c)
            y[r] = self.BitUnpack(v, self.gamma1 - 1, self.gamma1)
        return y

    def Power2Round(self, r: int) -> tuple[int, int]:
        """ 
            Power2Round(r) = (r1, r0) such that r = r1*2^d + r0 mod q 
            Reference: Algorithm 35: Power-of-two rounding, FIPS 204 page 40, slide 50
            Input: integer r in Z_q
            Output: integer (r1, r0)
        """
        r_plus = r % self.q
        two_pow_d = 2 ** self.d
        r0 = mod_pm(r_plus, two_pow_d)
        r1 = (r_plus - r0) // two_pow_d
        return r1, r0
    
    def Decompose(self, r: int) -> tuple[int, int]:
        """ 
            Decompose(r) = (r1, r0) such that r = r1*(2*gamma2) + r0 mod q, and -gamma2 < r0 <= gamma2
            Reference: Algorithm 36: Decomposition, FIPS 204 page 40, slide 50
            Input: integer r in Z_q
            Output: integer (r1, r0)
        """
        r_plus = r % self.q
        r0 = mod_pm(r_plus, 2 * self.gamma2)      
        if (r_plus - r0) == self.q - 1:
            r1 = 0
            r0 = r0 - 1
        else:
            r1 = (r_plus - r0) // (2 * self.gamma2)
        return r1, r0

    def HighBits(self, r: int) -> int:
        """ 
            HighBits(r) = r1 where Decompose(r) = (r1, r0)
            Reference: Algorithm 37: High bits, FIPS 204 page 40, slide 50
            Input: integer r in Z_q
            Output: integer r1
        """
        r1, r0 = self.Decompose(r)
        return r1
    
    def LowBits(self, r: int) -> int:
        """ 
            LowBits(r) = r0 where Decompose(r) = (r1, r0)
            Reference: Algorithm 38: Low bits, FIPS 204 page 41, slide 51
            Input: integer r in Z_q
            Output: integer r0
        """
        r1, r0 = self.Decompose(r)
        return r0

    def MakeHint(self, z: int, r: int) -> int:
        """ 
            Computes hint bit indicating whether adding z to r alters the high bits of r.
            Reference: Algorithm 39: Making hints, FIPS 204 page 41, slide 51
            Input: integers z, r in Z_q
            Output: integer h in {0, 1}
        """
        r1 = self.HighBits(r)
        v1 = self.HighBits((r + z) % self.q)
        return 1 if r1 != v1 else 0
    
    def UseHint(self, h: int, r: int) -> int:
        """ 
            Returns the high bits of r adjusted according to hint h.
            Reference: Algorithm 40: Using hints, FIPS 204 page 41, slide 51
            Input: integer h in {0, 1}, integer r in Z_q
            Output: integer r1 in Z_q with 0 <= r1 <= (q-1)/(2*gamma2) 
        """
        m = (self.q - 1) // (2 * self.gamma2)
        r1, r0 = self.Decompose(r)
        if h == 1 and r0 > 0:
            return (r1 + 1) % m
        if h == 1 and r0 <= 0:
            return (r1 - 1) % m
        return r1

    # def zetas(self, m: int) -> int:
    #     return pow(self.zeta, Dilithium.bitRev(m), self.q)

    def NTT(self, w: List[int]) -> List[int]:
        """ 
            Compute NTT(w)
            Reference: Algorithm 41: Number-theoretic transform (NTT), FIPS 204 page 43, slide 53
            Input: Polynomial w = (w[0], ..., w[255]) in R_q 
            Output: w = (w[0], ..., w[255]) in T_q
        """
        ans = [0] * 256
        for j in range(0, 256):
            ans[j] = w[j]
        m = 0
        len = 128
        while len >= 1:
            start = 0
            while start < 256:
                m = m + 1
                z = zetas[m]
                for j in range (start, start + len):
                    t = (z * ans[j + len]) % self.q
                    ans[j + len] = (ans[j] - t) % self.q
                    ans[j] = (ans[j] + t) % self.q
                start = start + 2 * len
            len = len // 2
        return ans
    
    def NTT_inv(self, w: List[int]) -> List[int]:
        """ 
            Compute the inverse of the NTT 
            Reference: Algorithm 42: Number-theoretic transform (NTT), FIPS 204 page 44, slide 54
            Input: w = (w[0], ..., w[255]) in T_q 
            Output: Polynomial w = (w[0], ..., w[255]) in R_q
        """
        ans = [0] * 256
        for j in range(0, 256):
            ans[j] = w[j]
        m = 256
        len = 1
        while len < 256:
            start = 0
            while start < 256:
                m = m - 1
                z = 0 -zetas[m]
                for j in range (start, start + len):
                    t = ans[j]
                    ans[j] = (t + ans[j + len]) % self.q
                    ans[j + len] = (t - ans[j + len]) % self.q
                    ans[j + len] = (z * ans[j + len]) % self.q
                start = start + 2 * len
            len = len * 2
        f = 8347681 # f = 256^{-1} mod q
        for j in range(0, 256):
            ans[j] = (f * ans[j]) % self.q 
        return ans
    
    @staticmethod
    def bitRev(n: int) -> int:
        """
            Transforms a byte by reversing the order of bits in its 8-bit binary expansion.
            Reference: Algorithm 43: Bit-reversal permutation, FIPS 204 page 44, slide 54
            Input: Integer n in [0, 255]
            Output: Integer result in [0, 255] whose binary expansion is the reverse of that of n
        """
        result = 0
        while n > 0:
            result = (result << 1) | (n & 1)
            n >>= 1
        return result
    
    def AddNTT(self, a: List[int], b: List[int]) -> List[int]:
        """ 
            Compute AddNTT(a, b) = NTT(a + b)
            Reference: Algorithm 44: Addition in the NTT domain, FIPS 204 page 45, slide 55
            Input: a = (a[0], ..., a[255]) in T_q, b = (b[0], ..., b[255]) in T_q
            Output: a + b = (a[0] + b[0], ..., a[255] + b[255]) in T_q
        """
        ans = [0] * 256
        for i in range(0, 256):
            ans[i] = (a[i] + b[i]) % self.q
        return ans
    
    def MultiplyNTT(self, a: List[int], b: List[int]) -> List[int]:
        """ 
            Compute MultiplyNTT(a, b) = NTT(a * b)
            Reference: Algorithm 45: Product of a and b in the NTT domain, FIPS 204 page 45, slide 55
            Input: a = (a[0], ..., a[255]) in T_q, b = (b[0], ..., b[255]) in T_q
            Output: a * b = (a[0] * b[0], ..., a[255] * b[255]) in T_q
        """
        ans = [0] * 256
        for i in range(0, 256):
            ans[i] = (a[i] * b[i]) % self.q
        return ans
    
    def AddVectorNTT(self, v: List[List[int]], w: List[List[int]]) -> List[List[int]]:
        """ 
            Compute the sum v + w of two vectors v, w in T_q^k
            Reference: Algorithm 46: Addition of vectors in the NTT domain, FIPS 204 page 45, slide 55
            Input: a = (a[0], ..., a[k-1]) in T_q^k, b = (b[0], ..., b[k-1]) in T_q^k
            Output: a + b = (a[0] + b[0], ..., a[k-1] + b[k-1]) in T_q^k
        """
        ans = [[0] * 256 for _ in range(len(v))]
        for i in range(len(v)):
            ans[i] = self.AddNTT(v[i], w[i])
        return ans
    
    def ScalarVectorNTT(self, c: List[int], v: List[List[int]]) -> List[List[int]]:
        """ 
            Compute the product c * v of a scalar c in T_q and a vector v over T_q^l
            Reference: Algorithm 47: Scalar multiplication of a vector in the NTT domain, FIPS 204 page 46, slide 56
            Input: c in T_q, v = (v[0], ..., v[k-1]) in T_q^l
            Output: c * v = (c * v[0], ..., c * v[k-1]) in T_q^l
        """
        ans = [[0] * 256 for _ in range(len(v))]
        for i in range(len(v)):
            ans[i] = self.MultiplyNTT(c, v[i])
        return ans
    
    def MatrixVectorNTT(self, M: List[List[List[int]]], v: List[List[int]]) -> List[List[int]]:
        """ 
            Compute the product M * v of a matrix M and a vector v over T_q
            Reference: Algorithm 48: Matrix-vector multiplication in the NTT domain, FIPS 204 page 46, slide 56
            Input: M = (A[0], ..., A[k-1]) in T_q^{k x l}, v = (v[0], ..., v[l-1]) in T_q^l
            Output: M * v = (sum(A[0][j] * v[j]), ..., sum(A[k-1][j] * v[j])) in T_q^k
        """
        ans = [[0] * 256 for _ in range(len(M))]
        for i in range(len(M)):
            for j in range(len(v)):
                ans[i] = self.AddNTT(ans[i], self.MultiplyNTT(M[i][j], v[j]))
        return ans
    
    def MontgomeryReduce(self, a: int) -> int:
        """
            Computes a * 2^{-32} mod q.
            Reference: Algorithm 49: Montgomery reduction, FIPS 204 page 50, slide 60
            Input: Integer a in [-2^{-31}*q, 2^{-31}*q]
            Output: r = a * 2^{-32} mod q
        """
        QINV = 58728449 # the inverse of 𝑞 modulo 2^32
        t = ((a % (2**32)) * QINV) % (2**32)
        r = (a - t * self.q) // (2**32)
        return r
             