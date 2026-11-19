class ECCPoint:
    def __init__(self, x=None, y=None, is_infinity=False):
        self.x = x
        self.y = y
        self.is_infinity = is_infinity

    def __str__(self):
        if self.is_infinity: return "Punkt w nieskończoności"
        return f"({self.x}, {self.y})"

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def mod(self, val):
        return val % self.p

    def mod_inverse(self, base):
        try:
            return pow(base, -1, self.p)
        except ValueError:
            return None

    def add(self, P, Q):
        if P.is_infinity: return Q
        if Q.is_infinity: return P
        if P.x == Q.x:
            if self.mod(P.y + Q.y) == 0: return ECCPoint(is_infinity=True)
            return self.double_point(P)
        num = self.mod(Q.y - P.y)
        den = self.mod(Q.x - P.x)
        den_inv = self.mod_inverse(den)
        if den_inv is None: return ECCPoint(is_infinity=True)
        _lambda = self.mod(num * den_inv)
        x3 = self.mod(_lambda * _lambda - P.x - Q.x)
        y3 = self.mod(_lambda * (P.x - x3) - P.y)
        return ECCPoint(x3, y3)

    def double_point(self, P):
        if P.is_infinity or P.y == 0: return ECCPoint(is_infinity=True)
        num = self.mod(3 * P.x * P.x + self.a)
        den = self.mod(2 * P.y)
        den_inv = self.mod_inverse(den)
        if den_inv is None: return ECCPoint(is_infinity=True)
        _lambda = self.mod(num * den_inv)
        x3 = self.mod(_lambda * _lambda - 2 * P.x)
        y3 = self.mod(_lambda * (P.x - x3) - P.y)
        return ECCPoint(x3, y3)

    def multiply(self, P, scalar):
        result = ECCPoint(is_infinity=True)
        addend = P
        k = scalar
        while k > 0:
            if (k & 1) == 1: result = self.add(result, addend)
            addend = self.double_point(addend)
            k >>= 1
        return result

# secp256k1
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
a = 0
b = 7
curve = EllipticCurve(a, b, p)
G = ECCPoint(
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

