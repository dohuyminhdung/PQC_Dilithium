from typing import List

class Dilithium:
    def __init__(self, q = 2**23 - 2**13 + 1, n = 256, 
                       k = 8, l = 7, eta = 2, d = 13, 
                       gamma1 = 2**19, tau = 60, beta = 120,
                       gamma2 = (2**23 - 2**13 + 1 - 1)/32,
                       lambda_ = 256, omega = 75):
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

def bitRev(n: int) -> int:
    """Bit-reverse the integer n."""
    result = 0
    while n > 0:
        result = (result << 1) | (n & 1)
        n >>= 1
    return result

def zetas(m: int):
    pass

def NTT(w: List[int], zeta : int) -> List[int]:
    ans = [0] * 256
    for j in range(0, 255):
        ans[j] = w[j]
    m = 0
    len = 128
    while len >= 1:
        start = 0
        while start < 256:
            m = m + 1
             