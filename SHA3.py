from typing import List

# --- round constants for Keccak-f[1600] (64-bit) ---
RC64 = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

class SHA3:
    """Algorithm Parameters and Other Variables
    A           A state array.
    b           The width of a KECCAK-p permutation in bits.
    c           The capacity of a sponge function.
    d           The length of the digest of a hash function or the requested length of the output of an XOF, in bits.
    f           The generic underlying function for the sponge construction.
    i_r         The round index for a KECCAK-p permutation.
    J           The input string to RawSHAKE128 or RawSHAKE256.
    l           For a KECCAK-p permutation, the binary logarithm of the lane size, i.e., log_2(w).
    Lane(i, j)  For a state array A, a string of all the bits of the lane whose x and y coordinates are i and j.
    M           The input string to a SHA-3 hash or XOF function.
    N           The input string to SPONGE[f, pad,r] or KECCAK[c].
    n_r         The number of rounds for a KECCAK-p permutation.
    pad         The generic padding rule for the sponge construction.
    Plane(j)    For a state array A, a string of all the bits of the plane whose y coordinate is j.
    r           The rate of a sponge function.
    RC          For a round of a KECCAK-p permutation, the round constant.
    w           The lane size of a KECCAK-p permutation in bits, i.e., b/25.
    """
    """Other parameters:
    """
    def __init__ (self, b = 1600, w = 64, l = 6):
        self.b = b
        self.l = l
        self.w = w
        
    def theta(self, A: List[List[List[int]]]) -> List[List[List[int]]]:
        C = [[0 for _ in range(self.w)] for _ in range(5)]
        for x in range(5):
            for z in range(self.w):
                C[x][z] = A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z]
        D = [[0 for _ in range(self.w)] for _ in range(5)]
        for x in range(5):
            for z in range(self.w):
                D[x][z] = C[(x-1) % 5][z] ^ C[(x+1) % 5][(z-1) % self.w]
        A_ = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    A_[x][y][z] = A[x][y][z] ^ D[x][z]
        return A_

    def rho(self, A: List[List[List[int]]]) -> List[List[List[int]]]:
        A_ = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for z in range(self.w): 
            A_[0][0][z] = A[0][0][z]
        x, y = 1, 0
        for t in range (0, 24):
            for z in range(self.w):
                A_[x][y][z] = A[x][y][(z-(t+1)*(t+2)//2) % self.w]
            x, y = y, (2*x + 3*y) % 5
        return A_
    
    def pi(self, A: List[List[List[int]]]) -> List[List[List[int]]]:
        A_ = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    A_[x][y][z] = A[(x+3*y) % 5][x][z]
        return A_
    
    def chi(self, A: List[List[List[int]]]) -> List[List[List[int]]]:
        A_ = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    A_[x][y][z] = A[x][y][z] ^ ((A[(x+1) % 5][y][z] ^ 1) & A[(x+2) % 5][y][z])
        return A_
    
    @staticmethod
    def rc(t : int) -> int:
        if t % 255 == 0:
            return 1
        R = 0x80
        for i in range(1, t % 255 + 1):
            R <<= 1
            if R & 0x100:
                R ^= 0b100011101
            R &= 0xff
        return R & 1
     
    # def iota(self, A: List[List[List[int]]], i_r: int) -> List[List[List[int]]]:
    #     A_ = [[[A[x][y][z] for z in range(self.w)] for y in range(5)] for x in range(5)]
    #     RC = [0] * self.w
    #     for j in range(0, self.l + 1):
    #         RC[(2**j) - 1] = SHA3.rc(j + 7 * i_r)
    #     for z in range(self.w):
    #         A_[0][0][z] = A_[0][0][z] ^ RC[z]
    #     return A_
    def iota(self, A: List[List[List[int]]], i_r: int) -> List[List[List[int]]]:
        A_ = [[[A[x][y][z] for z in range(self.w)] for y in range(5)] for x in range(5)]
        rc = RC64[i_r]  # 64-bit integer
        for z in range(self.w):
            bit = (rc >> z) & 1
            A_[0][0][z] ^= bit
        return A_
    
    def Rnd(self, A: List[List[List[int]]], i_r) -> List[List[List[int]]]:
        A = self.theta(A)
        A = self.rho(A)
        A = self.pi(A)
        A = self.chi(A)
        A = self.iota(A, i_r)
        return A
    
    def keccak_p(self, s: List[int], n_r: int) -> List[int]:
        """Algorithm 7: KECCAK-p[b, n_r](S)
            Input:
                string S of length b;
                number of rounds n_r.
            Output:
                string S' of length b.
        """
        A = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    A[x][y][z] = s[self.w * (5*y + x) + z]                  
        for i_r in range( (12 + 2*self.l - n_r) , (12 + 2*self.l)):
            A = self.Rnd(A, i_r)
        s_: List[int] = [] 
        for y in range(5):
            for x in range(5):
                for z in range(self.w):
                    s_.append(A[x][y][z])
        return s_
    
    # KECCAK-f[b] = KECCAK-p[b, 12+2l].
    # SHA-3 function == KECCAK-f[1600] == KECCAK-p[1600, 24]  
    # def sponge(N: bytes, d: int) -> bytes:
        """Algorithm 8: SPONGE[f, pad, r](N, d)
            Construction:
                f: An underlying function on fixed-length strings
                r: A parameter called the rate
                pad: A padding rule
            Input:
                string N
                nonnegative integer d
            Output:
                string Z such that len(Z)=d
        """
        ### Set up input message ###
            # 1. Let P=N || pad(r, len(N)).
            # 2. Let n=len(P)/r.
            # 3. Let c=b-r.
            # 4. Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P_0 || … || P_{n-1}.
        ### Absorbing phase ###
            # 5. Let S=0^b
            # 6. For i from 0 to n-1, let S=f(S xor (P_i || 0^c)).
        ### Squeezing phase ###
            # 7. Let Z be the empty string.
            # 8. Let Z=Z || Trunc_r(S).
            # 9. If d <= |Z|, then return Trunc_d(Z); else continue.
            # 10. Let S=f(S), and continue with Step 8.


    @staticmethod
    def pad10_mul_1(x: int, m: int) -> List[int]:
        j = (-m - 2) % x
        return [1] + [0] * j + [1]
    
    
    # KECCAK[c] (N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600–c] (N, d).
    """
        SHA3-224(M) = KECCAK[448] (M ||01, 224);
        SHA3-256(M) = KECCAK[512] (M || 01, 256);
        SHA3-384(M) = KECCAK[768] (M ||01, 384);
        SHA3-512(M) = KECCAK[1024](M || 01, 512).

        SHAKE128(M, d) = KECCAK[256] (M || 1111, d),
        SHAKE256(M, d) = KECCAK[512] (M || 1111, d).
    """
    
def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for b in data:
        for i in range(8):  # LSB trước
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits: List[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be divisible by 8")

    result = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            byte_val |= (bits[i + j] & 1) << j
        result.append(byte_val)
    return bytes(result)

def Trunc(X: List[int], s: int) -> List[int]:
    return X[:s]

class SHAKE_128:
    """ 
        KECCAK[c] (N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600-c] (N, d).
        SHAKE128(M, d) = KECCAK[256] (M || 1111, d),
    """
    def __init__ (self):
        self.sha3 = SHA3()
        self.c = 256
        self.r = 1600 - self.c

        self.absorbed: bool = False
        self.S = [0] * self.sha3.b
        self.buffer: List[int] = []
        self.pos: int = 0
        self.M: List[int] = []        
        

    def update(self, N: bytes):
        if self.absorbed:
            raise AttributeError("In SHA3/SHAKE, you can only absorb once")
        self.absorbed = True
        self.M = bytes_to_bits(N) + [1,1,1,1]
        P: List[int] = self.M + SHA3.pad10_mul_1(self.r ,len(self.M))
        # if len(P) % self.r != 0:
        #     raise ValueError("P length not multiple of r")
        n = len(P)//self.r
        c = self.sha3.b - self.r
        S: List[int] = [0] * self.sha3.b
        for i in range(n):
            Pi = P[i*self.r : (i+1)*self.r] + ([0] * c)
            S = [S[j] ^ Pi[j] for j in range(self.sha3.b)]
            S = self.sha3.keccak_p(S, 24)
        self.S = S
        # prepare first buffer for squeezing
        self.buffer = Trunc(self.S, self.r)
        self.pos = 0
        
    def read(self, d: int) -> bytes:
        if not self.absorbed:
            raise AttributeError("Call update() before read()")
        d *= 8
        Z: List[int] = []
        while len(Z) < d:
            if self.pos == len(self.buffer):
                self.S = self.sha3.keccak_p(self.S, 24)
                self.buffer = Trunc(self.S, self.r)
                self.pos = 0
            take = min(d - len(Z), len(self.buffer) - self.pos)
            Z.extend(self.buffer[self.pos : self.pos + take])
            self.pos += take
        return bits_to_bytes(Z)
    

class SHAKE_256:
    """ 
        KECCAK[c] (N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600-c] (N, d).
        SHAKE256(M, d) = KECCAK[512] (M || 1111, d).
    """
    def __init__ (self):
        self.sha3 = SHA3()
        self.c = 512
        self.r = 1600 - self.c

        self.absorbed: bool = False
        self.S = [0] * self.sha3.b
        self.buffer: List[int] = []
        self.pos: int = 0
        self.M: List[int] = []        
        

    def update(self, N: bytes):
        if self.absorbed:
            raise AttributeError("In SHA3/SHAKE, you can only absorb once")
        self.absorbed = True
        self.M = bytes_to_bits(N) + [1,1,1,1]
        P: List[int] = self.M + SHA3.pad10_mul_1(self.r ,len(self.M))
        # if len(P) % self.r != 0:
        #     raise ValueError("P length not multiple of r")
        n = len(P)//self.r
        c = self.sha3.b - self.r
        S: List[int] = [0] * self.sha3.b
        for i in range(n):
            Pi = P[i*self.r : (i+1)*self.r] + ([0] * c)
            S = [S[j] ^ Pi[j] for j in range(self.sha3.b)]
            S = self.sha3.keccak_p(S, 24)
        self.S = S
        # prepare first buffer for squeezing
        self.buffer = Trunc(self.S, self.r)
        self.pos = 0
        
    def read(self, d: int) -> bytes:
        if not self.absorbed:
            raise AttributeError("Call update() before read()")
        d *= 8
        Z: List[int] = []
        while len(Z) < d:
            if self.pos == len(self.buffer):
                self.S = self.sha3.keccak_p(self.S, 24)
                self.buffer = Trunc(self.S, self.r)
                self.pos = 0
            take = min(d - len(Z), len(self.buffer) - self.pos)
            Z.extend(self.buffer[self.pos : self.pos + take])
            self.pos += take
        return bits_to_bytes(Z)