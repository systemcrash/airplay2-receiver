import random
from hashlib import sha512

#
# Inspired from pyhomekit: https://github.com/henridwyer/pyhomekit
#
from hexdump import hexdump

N_3072 = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
           8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
           302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
           A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
           49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
           FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
           670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
           180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
           3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
           04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
           B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
           1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
           BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
           E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"""

N = int(''.join(N_3072.split()), 16)
PAD_L = N.bit_length() // 8
g = 5

SALT_BITS = 128
RANDOM_BITS = 512
password = ''


def H(*args, sep=b'', pad=False):
    # convert to bytes if necessary
    byte_args = []
    for arg in args:
        if isinstance(arg, int):
            arg = to_bytes(arg, False)
        elif isinstance(arg, str):
            arg = arg.encode('utf-8')
        if pad:
            arg = b'\x00' * (PAD_L - len(arg)) + arg
        byte_args.append(arg)
    return int(sha512(sep.join(byte_args)).hexdigest(), 16)


def random_int(n_bits=RANDOM_BITS):
    return random.SystemRandom().getrandbits(n_bits) % N


def to_bytes(value, little_endian=False):
    if little_endian:
        order = 'little'
    else:
        order = 'big'
    return value.to_bytes(-(-value.bit_length() // 8), order)


def from_bytes(value, little_endian=False):
    if little_endian:
        order = 'little'
    else:
        order = 'big'
    return int.from_bytes(value, order)


class Srp():
    def __init__(self):
        self.g = g
        self.N = N

    @property
    def salt(self):
        return to_bytes(self.s)

    @property
    def session_key(self):
        return to_bytes(self.K)

    def dumpAll(self):
        print("Salt")
        hexdump(to_bytes(self.s))
        print("x")
        hexdump(to_bytes(self.x))
        print("a")
        hexdump(to_bytes(self.a))
        print("b")
        hexdump(to_bytes(self.b))
        print("A")
        hexdump(to_bytes(self.A))
        print("B")
        hexdump(to_bytes(self.B))
        print("Verifier")
        hexdump(to_bytes(self.v))
        print("u")
        hexdump(to_bytes(self.u))

        print("S")
        hexdump(to_bytes(self.S))
        print("K")
        hexdump(to_bytes(self.K))
        print("M1")
        hexdump(to_bytes(self.M1))
        print("M2")
        hexdump(to_bytes(self.M2))


class SRPServer(Srp):
    def __init__(self, username, password):
        super(SRPServer, self).__init__()
        self.username = username
        self.k = H(self.N, self.g, pad=True)
        self.s = random_int(n_bits=SALT_BITS)  # type: int
        self.x = H(self.s, H(username, password, sep=b":"))  # type: int
        self.v = pow(self.g, self.x, self.N)
        self.b = random_int(n_bits=RANDOM_BITS)
        self.B = (self.k * self.v + pow(self.g, self.b, self.N)) % self.N  # type: int
        self.a = 0  # type: int
        self.A = 0  # type: int
        self.u = 0  # type: int
        self.S = 0  # type: int
        self.K = 0  # type: int
        self.M1 = 0  # type: int
        self.M2 = 0  # type: int
        self.X = 0  # type: int
        self.state = 0
        self.signing_key = None  # type: Optional[ed25519.SigningKey]
        self.verifying_key = None  # type: Optional[ed25519.VerifyingKey]
        self.device_info = b''  # type: bytes
        self.device_signature = b''  # type: bytes
        self.accessory_pairing_id = b''  # type: bytes
        self.accessory_ltpk = b''  # type: bytes
        self.accessory_signature = b''  # type: bytes

    # For TESTS only
    def testInit(self, username, password, salt, a, b, A, B):
        self.username = username
        self.g = g
        self.N = N
        self.k = H(self.N, self.g, pad=True)
        self.s = from_bytes(salt)  # type: int
        self.x = H(self.s, H(username, password, sep=b":"))  # type: int
        self.v = pow(self.g, self.x, self.N)
        self.b = from_bytes(b)
        self.B = from_bytes(B)  # type: int
        self.a = from_bytes(a)  # type: int
        self.A = from_bytes(A)  # type: int
        self.u = 0  # type: int
        self.S = 0  # type: int
        self.K = 0  # type: int
        self.M1 = 0  # type: int
        self.M2 = 0  # type: int
        self.X = 0  # type: int
        self.state = 0
        self.signing_key = None  # type: Optional[ed25519.SigningKey]
        self.verifying_key = None  # type: Optional[ed25519.VerifyingKey]
        self.device_info = b''  # type: bytes
        self.device_signature = b''  # type: bytes
        self.accessory_pairing_id = b''  # type: bytes
        self.accessory_ltpk = b''  # type: bytes
        self.accessory_signature = b''  # type: bytes

    @property
    def public_key(self):
        return to_bytes(self.B)

    @property
    def proof(self):
        return to_bytes(self.M2)

    def set_client_public(self, A):
        self.A = from_bytes(A)
        self.u = H(self.A, self.B, pad=True)
        self.S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N) % self.N
        self.K = H(self.S)
        self.M1 = H(H(self.N) ^ H(self.g), H(self.username), self.s, self.A, self.B, self.K)

    def verify(self, M1_client):
        if self.M1 != from_bytes(M1_client):
            raise Exception("Authentication failed - invalid proof")
        self.M2 = H(self.A, self.M1, self.K)
        return True


class SrpClient(Srp):
    def __init__(self, username, password, salt):
        super(SrpClient, self).__init__()
        self.username = username
        self.g = g
        self.N = N
        self.k = H(self.N, self.g, pad=True)
        self.s = from_bytes(salt)  # type: int
        self.x = H(self.s, H(username, password, sep=b":"))  # type: int
        self.v = pow(self.g, self.x, self.N)
        self.b = 0  # type: int
        self.B = 0  # type: int
        self.a = random_int(n_bits=RANDOM_BITS)  # type: int
        self.A = pow(self.g, self.a, self.N)
        self.u = 0  # type: int
        self.S = 0  # type: int
        self.K = 0  # type: int
        self.M1 = 0  # type: int
        self.M2 = 0  # type: int
        self.X = 0  # type: int
        self.state = 0
        self.signing_key = None  # type: Optional[ed25519.SigningKey]
        self.verifying_key = None  # type: Optional[ed25519.VerifyingKey]
        self.device_info = b''  # type: bytes
        self.device_signature = b''  # type: bytes
        self.accessory_pairing_id = b''  # type: bytes
        self.accessory_ltpk = b''  # type: bytes
        self.accessory_signature = b''  # type: bytes

    def set_server_public(self, B):
        self.B = from_bytes(B)
        self.u = H(self.A, self.B, pad=True)
        # S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
        self.S = pow(self.B - (self.k * pow(self.g, self.x, self.N)), self.a + (self.u * self.x), self.N) % self.N
        self.K = H(self.S)
        self.M1 = H(H(self.N) ^ H(self.g), H(self.username), self.s, self.A, self.B, self.K)

    @property
    def public_key(self):
        return to_bytes(self.A)

    @property
    def proof(self):
        return to_bytes(self.M1)

    def verify(self, M2_server):
        if self.M2 != from_bytes(M2_server):
            raise Exception("Authentication failed - invalid proof")
        return True
