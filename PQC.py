from typing import List
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHAKE256, SHAKE128

def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'little')

def H(str: bytes, outlen: int) -> bytes:
    """ 
        Hash function H(str, l) = SHAKE256(str, 8*l)
        Reference: FIPS 204, page 14, slide 24
        Input: str is a byte string of any length, outlen is the desired output length in bytes
        Output: A byte string of length outlen
    """
    shake = SHAKE256.new()
    shake.update(str)
    return shake.read(outlen)

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
                       gamma2 = (2**23 - 2**13 + 1 - 1)/32,
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

    
    def KeyGen(self):
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
    
    def KeyGen_internal(self, xi: bytes):
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
        t1, t0 = self.Power2Round(t)
        pk = self.pkEncode(rho, t1)
        tr = H(pk, 64)
        sk = self.skEncode(rho, K, tr, s1, s2, t0)
        return pk, sk 

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
        ctx = SHAKE256.new()   #H.Init
        ctx.update(seed)       #H.Absorb(ctx, seed)
        while j < 256:
            z = ctx.read(1)  #H.Squeeze(ctx, 1)
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

    def zetas(self, m: int) -> int:
        return pow(self.zeta, Dilithium.bitRev(m), self.q)

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
                z = self.zetas(m)
                for j in range (start, start + len - 1):
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
        while len <= 256:
            start = 0
            while start < 256:
                m = m - 1
                z = self.zetas(m)
                for j in range (start, start + len - 1):
                    t = ans[j]
                    ans[j] = (t + ans[j + len]) % self.q
                    ans[j + len] = (t - ans[j + len]) % self.q
                    ans[j + len] = (z * ans[j + len]) % self.q
                start = start + 2 * len
            len = len * 2
        f = 8347681
        for j in range(0, 256):
            ans[j] = (f * ans[j]) % self.q 
        return ans
    
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
    
    
             