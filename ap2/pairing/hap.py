import struct
import socket
import hashlib
import threading

from Crypto.PublicKey import RSA
from hexdump import hexdump

import hkdf
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import nacl.signing
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA1

from . import srp
from .srp import to_bytes
from ..rtsp_client import RTSPConnection

SERVER_VERSION = "366.0"
HTTP_CT_BPLIST = "application/x-apple-binary-plist"
HTTP_CT_OCTET = "application/octet-stream"
HTTP_CT_PARAM = "text/parameters"
HTTP_CT_IMAGE = "image/jpeg"
HTTP_CT_DMAP = "application/x-dmap-tagged"
ENABLE_PLIST_DUMP = True


class PairingMethod:
    PAIR_SETUP = b'\x00'
    PAIR_SETUP_AUTH = b'\x01'
    PAIR_VERIFY = b'\x02'
    ADD_PAIRING = b'\x03'
    REMOVE_PAIRING = b'\x04'
    LIST_PAIRINGS = b'\x05'


class PairingErrors:
    RESERVED = 0
    UNKNOWN = 1
    AUTHENTICATION = 2
    BACKOFF = 3
    MAXPEERS = 4
    MAXTRIES = 5
    UNAVAILABLE = 6
    BUSY = 7


class PairingFlags:
    TRANSIENT = b'\x10'


class PairingState:
    M1 = b'\x01'
    M2 = b'\x02'
    M3 = b'\x03'
    M4 = b'\x04'
    M5 = b'\x05'
    M6 = b'\x06'


class Tlv8:
    class Tag:
        METHOD = 0
        IDENTIFIER = 1
        SALT = 2
        PUBLICKEY = 3
        PROOF = 4
        ENCRYPTEDDATA = 5
        STATE = 6
        ERROR = 7
        RETRYDELAY = 8
        CERTIFICATE = 9
        SIGNATURE = 10
        PERMISSIONS = 11
        FRAGMENTDATA = 12
        FRAGMENTLAST = 13
        FLAGS = 19
        SEPARATOR = 255

    @staticmethod
    def decode(req, debug=True):
        res = {}
        ptr = 0
        while ptr < len(req):
            tag = req[ptr]
            length = req[ptr + 1]
            value = req[ptr + 2:ptr + 2 + length]
            # print("dec tag=%d length=%d value=%s" % (tag, length, value.hex()))
            if tag in res:
                res[tag] = res[tag] + value
            else:
                res[tag] = value
            ptr += 2 + length

        return res

    @staticmethod
    def encode(req):
        res = b""
        for i in range(0, len(req), 2):
            tag = req[i]
            value = req[i + 1]
            length = len(value)

            # print("enc tag=%d length=%d value=%s" % (tag, length, value.hex()))
            if length <= 255:
                res += bytes([tag]) + bytes([length]) + value
            else:
                for i in range(0, length // 255):
                    res += bytes([tag]) + b"\xff" + value[i * 255:(i + 1) * 255]
                left = length % 255
                res += bytes([tag]) + bytes([left]) + value[-left:]

        return res


class HapClient:
    def __init__(self, ap2sender_callback):
        self.ap2sender_callback = ap2sender_callback
        self.server_pk = None
        self.pairing_status = self.PairingStatus()

    class PairingStatus():
        def __init__(self):
            self.global_status = None
            self.method = None
            self.state = None
            self.step = None
            self.flags = None
            self.error = None
            self.encrypted = False

        @property
        def pairing_step(self):
            return self.step

    def request(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP:
            res = self.pair_setup(req)
        return Tlv8.encode(res)

    def pushTestClientKeys(self, srp):
        salt = b'\xBE\xB2\x53\x79\xD1\xA8\x58\x1E\xB5\xA7\x27\x67\x3A\x24\x41\xEE'
        a = b'\x60\x97\x55\x27\x03\x5c\xf2\xad\x19\x89\x80\x6f\x04\x07\x21\x0b\xc8\x1e\xdc\x04\xe2\x76\x2a\x56\xaf\xd5\x29\xdd\xda\x2d\x43\x93'
        A = b'\xfa\xb6\xf5\xd2\x61\x5d\x1e\x32\x35\x12\xe7\x99' \
            b'\x1c\xc3\x74\x43\xf4\x87\xda\x60\x4c\xa8\xc9\x23' \
            b'\x0f\xcb\x04\xe5\x41\xdc\xe6\x28\x0b\x27\xca\x46' \
            b'\x80\xb0\x37\x4f\x17\x9d\xc3\xbd\xc7\x55\x3f\xe6' \
            b'\x24\x59\x79\x8c\x70\x1a\xd8\x64\xa9\x13\x90\xa2' \
            b'\x8c\x93\xb6\x44\xad\xbf\x9c\x00\x74\x5b\x94\x2b' \
            b'\x79\xf9\x01\x2a\x21\xb9\xb7\x87\x82\x31\x9d\x83' \
            b'\xa1\xf8\x36\x28\x66\xfb\xd6\xf4\x6b\xfc\x0d\xdb' \
            b'\x2e\x1a\xb6\xe4\xb4\x5a\x99\x06\xb8\x2e\x37\xf0' \
            b'\x5d\x6f\x97\xf6\xa3\xeb\x6e\x18\x20\x79\x75\x9c' \
            b'\x4f\x68\x47\x83\x7b\x62\x32\x1a\xc1\xb4\xfa\x68' \
            b'\x64\x1f\xcb\x4b\xb9\x8d\xd6\x97\xa0\xc7\x36\x41' \
            b'\x38\x5f\x4b\xab\x25\xb7\x93\x58\x4c\xc3\x9f\xc8' \
            b'\xd4\x8d\x4b\xd8\x67\xa9\xa3\xc1\x0f\x8e\xa1\x21' \
            b'\x70\x26\x8e\x34\xfe\x3b\xbe\x6f\xf8\x99\x98\xd6' \
            b'\x0d\xa2\xf3\xe4\x28\x3c\xbe\xc1\x39\x3d\x52\xaf' \
            b'\x72\x4a\x57\x23\x0c\x60\x4e\x9f\xbc\xe5\x83\xd7' \
            b'\x61\x3e\x6b\xff\xd6\x75\x96\xad\x12\x1a\x87\x07' \
            b'\xee\xc4\x69\x44\x95\x70\x33\x68\x6a\x15\x5f\x64' \
            b'\x4d\x5c\x58\x63\xb4\x8f\x61\xbd\xbf\x19\xa5\x3e' \
            b'\xab\x6d\xad\x0a\x18\x6b\x8c\x15\x2e\x5f\x5d\x8c' \
            b'\xad\x4b\x0e\xf8\xaa\x4e\xa5\x00\x88\x34\xc3\xcd' \
            b'\x34\x2e\x5e\x0f\x16\x7a\xd0\x45\x92\xcd\x8b\xd2' \
            b'\x79\x63\x93\x98\xef\x9e\x11\x4d\xfa\xaa\xb9\x19' \
            b'\xe1\x4e\x85\x09\x89\x22\x4d\xdd\x98\x57\x6d\x79' \
            b'\x38\x5d\x22\x10\x90\x2e\x9f\x9b\x1f\x2d\x86\xcf' \
            b'\xa4\x7e\xe2\x44\x63\x54\x65\xf7\x10\x58\x42\x1a' \
            b'\x01\x84\xbe\x51\xdd\x10\xcc\x9d\x07\x9e\x6f\x16' \
            b'\x04\xe7\xaa\x9b\x7c\xf7\x88\x3c\x7d\x4c\xe1\x2b' \
            b'\x06\xeb\xe1\x60\x81\xe2\x3f\x27\xa2\x31\xd1\x84' \
            b'\x32\xd7\xd1\xbb\x55\xc2\x8a\xe2\x1f\xfc\xf0\x05' \
            b'\xf5\x75\x28\xd1\x5a\x88\x88\x1b\xb3\xbb\xb7\xfe'

        srp.s = salt
        srp.a = a
        srp.A = A

    def set_state_from_response(self, response):
        decoded_tlvs = Tlv8.decode(response)
        
        self.pairing_status.state = decoded_tlvs[Tlv8.Tag.STATE]
        if Tlv8.Tag.ERROR in decoded_tlvs:
            self.pairing_status.error ="Some error occured..."
        return 

    def list_pairings(self):
        req = [Tlv8.Tag.STATE, PairingState.M1,
                Tlv8.Tag.METHOD, PairingMethod.LIST_PAIRINGS]
        return Tlv8.encode(req)
        
    def do_pairing(self):
        self.pairing_status.global_status = "PENDING"
        self.pairing_status.method = PairingMethod.PAIR_SETUP_AUTH
        self.pairing_status.flags = PairingFlags.TRANSIENT
        self.pairing_status.state = PairingState.M1
        self.pairing_status.error = "None"

        response = self.pair_setup_m1_m2()
        self.set_state_from_response(response)

        if self.pairing_status.state == PairingState.M2:
            response = self.pair_setup_m2_m3(response)
            self.set_state_from_response(response)

        if self.pairing_status.state == PairingState.M4:
            response = self.pair_setup_m4(response)

        return

    # Initialise M1 setup
    def pair_setup_m1_m2(self):
        req = [Tlv8.Tag.METHOD, self.pairing_status.method,
               Tlv8.Tag.STATE, self.pairing_status.state,
               Tlv8.Tag.FLAGS, self.pairing_status.flags]
        # Sender will send http request, and then go on with do_pairing
        return self.ap2sender_callback(Tlv8.encode(req), self.pairing_status)

    def pair_verify(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            print("-----\tPair-Verify [1/2]")
            res = self.pair_verify_m1_m2(req[Tlv8.Tag.PUBLICKEY])
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            print("-----\tPair-Verify [2/2]")
            res = self.pair_verify_m3_m4(req[Tlv8.Tag.ENCRYPTEDDATA])
            self.encrypted = True
        return Tlv8.encode(res)

    # Receive M2 response, Init M3
    def pair_setup_m2_m3(self, body):
        tvl_resp = Tlv8.decode(body)

        self.server_pk = tvl_resp[Tlv8.Tag.PUBLICKEY]
        self.salt = tvl_resp[Tlv8.Tag.SALT]

        self.ctx = srp.SrpClient(b"Pair-Setup", b"3939", self.salt)
        self.ctx.set_server_public(self.server_pk)

        req = [Tlv8.Tag.STATE, PairingState.M3,
               Tlv8.Tag.PUBLICKEY, self.ctx.public_key,
               Tlv8.Tag.PROOF, self.ctx.proof]

        # Sender will send http request, and then go on with do_pairing
        self.pairing_status.state = PairingState.M3
        return self.ap2sender_callback(Tlv8.encode(req), self.pairing_status)

    # Receive M4
    def pair_setup_m4(self, body):
        tvl_resp = Tlv8.decode(body)

        server_proof = tvl_resp[Tlv8.Tag.PROOF]
        encrypted = tvl_resp[Tlv8.Tag.ENCRYPTEDDATA]

        prk = hkdf.hkdf_extract(b"Pair-Setup-Encrypt-Salt", self.ctx.session_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Setup-Encrypt-Info", 32)
        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg04")

        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]

        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)
        tlv_decoded = Tlv8.decode(dec_tlv)
        cert = tlv_decoded[Tlv8.Tag.CERTIFICATE]
        sig = tlv_decoded[Tlv8.Tag.SIGNATURE]

        prk = hkdf.hkdf_extract(b"MFi-Pair-Setup-Salt", self.ctx.session_key)
        message_to_check = hkdf.hkdf_expand(prk, b"MFi-Pair-Setup-Info", 32)
        message_to_check_digest = SHA1.new()
        message_to_check_digest.update(message_to_check)

        rsapubfile = open("./sonos-pubkey.pem","r")
        rsapubkey = rsapubfile.read()
        rsakey = RSA.importKey(rsapubkey)
        signer = PKCS1_v1_5.new(rsakey)

        if signer.verify(message_to_check_digest, sig):
            print("MFI Signature OK")
        else:
            print("MFI Signature KO")

        assert self.ctx.verify(server_proof)
        self.shared_key = self.ctx.session_key
        self.pairing_status.encrypted = True

        # Sender will send http request, and then go on with do_pairing
        self.pairing_status.global_status = "PAIRED"
        return self.ap2sender_callback(None, self.pairing_status)

    def pair_setup_m5_m6(self, encrypted):
        print("-----\tPair-Setup [3/5]")
        dec_tlv, session_key = self.pair_setup_m5_m6_1(encrypted)
        print("-----\tPair-Setup [4/5]")
        self.pair_setup_m5_m6_2(dec_tlv)
        print("-----\tPair-Setup [5/5]")
        enc_tlv, tag = self.pair_setup_m5_m6_3(session_key)

        return [Tlv8.Tag.STATE, PairingState.M6,
                Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag]

    def pair_setup_m5_m6_1(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Setup-Encrypt-Salt", self.ctx.session_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Setup-Encrypt-Info", 32)
        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg05")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)

        return Tlv8.decode(dec_tlv), session_key

    def pair_setup_m5_m6_2(self, dec_tlv):
        self.device_id = dec_tlv[Tlv8.Tag.IDENTIFIER]
        self.device_ltpk = dec_tlv[Tlv8.Tag.PUBLICKEY]
        device_sig = dec_tlv[Tlv8.Tag.SIGNATURE]

        prk = hkdf.hkdf_extract(b"Pair-Setup-Controller-Sign-Salt", self.ctx.session_key)
        device_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Controller-Sign-Info", 32)
        device_info = device_x + self.device_id + self.device_ltpk

        verify_key = nacl.signing.VerifyKey(self.device_ltpk)
        verify_key.verify(device_info, device_sig)

    def pair_setup_m5_m6_3(self, session_key):
        prk = hkdf.hkdf_extract(b"Pair-Setup-Accessory-Sign-Salt", self.ctx.session_key)
        accessory_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Accessory-Sign-Info", 32)

        self.accessory_ltsk = nacl.signing.SigningKey.generate()
        self.accessory_ltpk = bytes(self.accessory_ltsk.verify_key)

        self.accessory_id = b"00000000-0000-0000-0000-f0989d7cbbab"

        accessory_info = accessory_x + self.accessory_id + self.accessory_ltpk
        accessory_signed = self.accessory_ltsk.sign(accessory_info)
        accessory_sig = accessory_signed.signature

        dec_tlv = Tlv8.encode([Tlv8.Tag.IDENTIFIER, self.accessory_id,
                               Tlv8.Tag.PUBLICKEY, self.accessory_ltpk,
                               Tlv8.Tag.SIGNATURE, accessory_sig])

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg06")
        enc_tlv, tag = c.encrypt_and_digest(dec_tlv)

        return enc_tlv, tag

    def pair_verify_m1_m2(self, client_public):
        self.client_curve_public = client_public

        self.accessory_curve = x25519.X25519PrivateKey.generate()
        self.accessory_curve_public = self.accessory_curve.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.accessory_shared_key = self.accessory_curve.exchange(
            x25519.X25519PublicKey.from_public_bytes(client_public))

        accessory_info = self.accessory_curve_public + self.accessory_id + client_public
        accessory_signed = self.accessory_ltsk.sign(accessory_info)
        accessory_sig = accessory_signed.signature

        sub_tlv = Tlv8.encode([Tlv8.Tag.IDENTIFIER, self.accessory_id,
                               Tlv8.Tag.SIGNATURE, accessory_sig])

        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg02")
        enc_tlv, tag = c.encrypt_and_digest(sub_tlv)

        return [Tlv8.Tag.STATE, PairingState.M2,
                Tlv8.Tag.PUBLICKEY, self.accessory_curve_public,
                Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag]

    def pair_verify_m3_m4(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg03")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)

        sub_tlv = Tlv8.decode(dec_tlv)
        device_id = sub_tlv[Tlv8.Tag.IDENTIFIER]
        device_sig = sub_tlv[Tlv8.Tag.SIGNATURE]

        device_info = self.client_curve_public + device_id + self.accessory_curve_public
        verify_key = nacl.signing.VerifyKey(self.device_ltpk)
        verify_key.verify(device_info, device_sig)

        return [Tlv8.Tag.STATE, PairingState.M4]


class Hap:
    def __init__(self):
        self.transient = False
        self.encrypted = False
        self.pair_setup_steps_n = 5

    def request(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP_AUTH:
            res = self.pair_setup(req)
        return Tlv8.encode(res)

    def pair_setup(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.STATE] == PairingState.M1 and \
                (req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP or
                req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP_AUTH) and \
                Tlv8.Tag.FLAGS in req and \
                req[Tlv8.Tag.FLAGS] == PairingFlags.TRANSIENT:
            self.transient = True
            self.pair_setup_steps_n = 2

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            print("-----\tPair-Setup [1/%d]" % self.pair_setup_steps_n)
            res = self.pair_setup_m1_m2()
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            print("-----\tPair-Setup [2/%d]" % self.pair_setup_steps_n)
            res = self.pair_setup_m3_m4(req[Tlv8.Tag.PUBLICKEY], req[Tlv8.Tag.PROOF])
            if self.transient:
                self.encrypted = True
        elif req[Tlv8.Tag.STATE] == PairingState.M5:
            res = self.pair_setup_m5_m6(req[Tlv8.Tag.ENCRYPTEDDATA])
        return Tlv8.encode(res)

    def pair_verify(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            print("-----\tPair-Verify [1/2]")
            res = self.pair_verify_m1_m2(req[Tlv8.Tag.PUBLICKEY])
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            print("-----\tPair-Verify [2/2]")
            res = self.pair_verify_m3_m4(req[Tlv8.Tag.ENCRYPTEDDATA])
            self.encrypted = True
        return Tlv8.encode(res)

    def pair_setup_m1_m2(self):
        self.ctx = srp.SRPServer(b"Pair-Setup", b"3939")
        server_public = self.ctx.public_key
        salt = self.ctx.salt

        return [Tlv8.Tag.STATE, PairingState.M2,
                Tlv8.Tag.SALT, salt,
                Tlv8.Tag.PUBLICKEY, server_public]

    def pair_setup_m3_m4(self, client_public, client_proof):
        self.ctx.set_client_public(client_public)
        assert self.ctx.verify(client_proof)

        self.accessory_shared_key = self.ctx.session_key
        server_proof = self.ctx.proof

        encryption_type = b'\x01'
        body = encryption_type + client_public
        
        # If method is PAIR_SETUP_AUTH, then we must provide the proof
        connection = RTSPConnection("192.168.28.163", 7000)
        connection.putrequest("POST", "/auth-setup", False, False)
        connection.putheader("CSeq", 1)
        connection.putheader("User-Agent", self.version_string())
        connection.putheader("Content-Length", 33)
        connection.putheader("Content-Type", HTTP_CT_BPLIST)
        connection.putheader("User-Agent", self.version_string())
        connection.putheader("X-Apple-HKP", 4)
        connection.endheaders()
        connection.send(body)

        res = connection.getresponse()

        if res.status == 200:
            data = res.read()

            cert_length = struct.unpack(">I", data[32:36])[0]
            cert = data[36:36 + cert_length]
            sig_length = struct.unpack(">I", data[36 + cert_length:40 + cert_length])[0]
            sig = data[40 + cert_length:]

            dec_tlv = Tlv8.encode([Tlv8.Tag.CERTIFICATE, cert,
                                   Tlv8.Tag.SIGNATURE, sig])

            c = ChaCha20_Poly1305.new(key=self.ctx.session_key, nonce=b"PS-Msg04")
            enc_tlv, tag = c.encrypt_and_digest(dec_tlv)

        return [Tlv8.Tag.STATE, PairingState.M4,
                Tlv8.Tag.PROOF, server_proof, Tlv8.Tag.ENCRYPTEDDATA, enc_tlv]

    def pair_setup_m5_m6(self, encrypted):
        print("-----\tPair-Setup [3/5]")
        dec_tlv, session_key = self.pair_setup_m5_m6_1(encrypted)
        print("-----\tPair-Setup [4/5]")
        self.pair_setup_m5_m6_2(dec_tlv)
        print("-----\tPair-Setup [5/5]")
        enc_tlv, tag = self.pair_setup_m5_m6_3(session_key)

        return [Tlv8.Tag.STATE, PairingState.M6,
                Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag]

    def pair_setup_m5_m6_1(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Setup-Encrypt-Salt", self.ctx.session_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Setup-Encrypt-Info", 32)
        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg05")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)

        return Tlv8.decode(dec_tlv), session_key

    def pair_setup_m5_m6_2(self, dec_tlv):
        self.device_id = dec_tlv[Tlv8.Tag.IDENTIFIER]
        self.device_ltpk = dec_tlv[Tlv8.Tag.PUBLICKEY]
        device_sig = dec_tlv[Tlv8.Tag.SIGNATURE]

        prk = hkdf.hkdf_extract(b"Pair-Setup-Controller-Sign-Salt", self.ctx.session_key)
        device_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Controller-Sign-Info", 32)
        device_info = device_x + self.device_id + self.device_ltpk

        verify_key = nacl.signing.VerifyKey(self.device_ltpk)
        verify_key.verify(device_info, device_sig)

    def pair_setup_m5_m6_3(self, session_key):
        prk = hkdf.hkdf_extract(b"Pair-Setup-Accessory-Sign-Salt", self.ctx.session_key)
        accessory_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Accessory-Sign-Info", 32)

        self.accessory_ltsk = nacl.signing.SigningKey.generate()
        self.accessory_ltpk = bytes(self.accessory_ltsk.verify_key)

        self.accessory_id = b"00000000-0000-0000-0000-f0989d7cbbab"

        accessory_info = accessory_x + self.accessory_id + self.accessory_ltpk
        accessory_signed = self.accessory_ltsk.sign(accessory_info)
        accessory_sig = accessory_signed.signature

        dec_tlv = Tlv8.encode([Tlv8.Tag.IDENTIFIER, self.accessory_id,
                               Tlv8.Tag.PUBLICKEY, self.accessory_ltpk,
                               Tlv8.Tag.SIGNATURE, accessory_sig])

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg06")
        enc_tlv, tag = c.encrypt_and_digest(dec_tlv)

        return enc_tlv, tag

    def pair_verify_m1_m2(self, client_public):
        self.client_curve_public = client_public

        self.accessory_curve = x25519.X25519PrivateKey.generate()
        self.accessory_curve_public = self.accessory_curve.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.accessory_shared_key = self.accessory_curve.exchange(
            x25519.X25519PublicKey.from_public_bytes(client_public))

        accessory_info = self.accessory_curve_public + self.accessory_id + client_public
        accessory_signed = self.accessory_ltsk.sign(accessory_info)
        accessory_sig = accessory_signed.signature

        sub_tlv = Tlv8.encode([Tlv8.Tag.IDENTIFIER, self.accessory_id,
                               Tlv8.Tag.SIGNATURE, accessory_sig])

        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg02")
        enc_tlv, tag = c.encrypt_and_digest(sub_tlv)

        return [Tlv8.Tag.STATE, PairingState.M2,
                Tlv8.Tag.PUBLICKEY, self.accessory_curve_public,
                Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag]

    def pair_verify_m3_m4(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg03")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)

        sub_tlv = Tlv8.decode(dec_tlv)
        device_id = sub_tlv[Tlv8.Tag.IDENTIFIER]
        device_sig = sub_tlv[Tlv8.Tag.SIGNATURE]

        device_info = self.client_curve_public + device_id + self.accessory_curve_public
        verify_key = nacl.signing.VerifyKey(self.device_ltpk)
        verify_key.verify(device_info, device_sig)

        return [Tlv8.Tag.STATE, PairingState.M4]


#
# Inspired from HAP-Python: https://github.com/ikalchev/HAP-python
#
class HAPSocket:
    """A socket implementing the HAP crypto. Just feed it as if it is a normal socket.
    This implementation is something like a Proxy pattern - some calls to socket
    methods are wrapped and some are forwarded as is.
    @note: HAP requires something like HTTP push. This implies we can have regular HTTP
    response and an outbound HTTP push at the same time on the same socket - a race
    condition. Thus, HAPSocket implements exclusive access to send and sendall to deal
    with this situation.
    """

    MAX_BLOCK_LENGTH = 0x400
    LENGTH_LENGTH = 2

    CIPHER_SALT = b"Control-Salt"

    class SocketType:
        # Use this if the socket if a connecttion to an HKP accessory
        ACCESSORY = 0
        # Use this if an accessory is connected
        DEVICE = 1

    def __init__(self, sock, shared_key, socket_type = SocketType.DEVICE):
        """Initialise from the given socket."""
        self.socket = sock
        if socket_type == self.SocketType.DEVICE:
            self.OUT_CIPHER_INFO = b"Control-Read-Encryption-Key"
            self.IN_CIPHER_INFO = b"Control-Write-Encryption-Key"
        else:
            self.OUT_CIPHER_INFO = b"Control-Write-Encryption-Key"
            self.IN_CIPHER_INFO = b"Control-Read-Encryption-Key"

        self.shared_key = shared_key
        self.out_count = 0
        self.in_count = 0
        self.out_lock = threading.RLock()  # for locking send operations

        self._set_ciphers()
        self.curr_in_total = None  # Length of the current incoming block
        self.num_in_recv = None  # Number of bytes received from the incoming block
        self.curr_in_block = None  # Bytes of the current incoming block

    def __getattr__(self, attribute_name):
        """Defer unknown behaviour to the socket"""
        return getattr(self.socket, attribute_name)

    def _get_io_refs(self):
        """Get `socket._io_refs`."""
        return self.socket._io_refs

    def _set_io_refs(self, value):
        """Set `socket._io_refs`."""
        self.socket._io_refs = value

    _io_refs = property(_get_io_refs, _set_io_refs)
    """`socket.makefile` uses a `SocketIO` to wrap the socket stream. Internally,
    this uses `socket._io_refs` directly to determine if a socket object needs to be
    closed when its FileIO object is closed.
    Because `_io_refs` is assigned as part of this process, it bypasses getattr. To get
    around this, let's make _io_refs our property and proxy calls to the socket.
    """

    def makefile(self, *args, **kwargs):
        """Return a file object that reads/writes to this object.
        We need to implement this, otherwise the socket's makefile will use the socket
        object and we won't en/decrypt.
        """
        return socket.socket.makefile(self, *args, **kwargs)

    def _set_ciphers(self):
        """Generate out/inbound encryption keys and initialise respective ciphers."""

        prk = hkdf.hkdf_extract(self.CIPHER_SALT, self.shared_key)
        self.outgoing_key = hkdf.hkdf_expand(prk, self.OUT_CIPHER_INFO, 32)

        prk = hkdf.hkdf_extract(self.CIPHER_SALT, self.shared_key)
        self.incoming_key = hkdf.hkdf_expand(prk, self.IN_CIPHER_INFO, 32)

    def _with_out_lock(func):
        """Return a function that acquires the outbound lock and executes func."""

        def _wrapper(self, *args, **kwargs):
            with self.out_lock:
                return func(self, *args, **kwargs)

        return _wrapper

    def recv_into(self, buffer, nbytes=1042, flags=0):
        """Receive and decrypt up to nbytes in the given buffer."""
        data = self.recv(nbytes, flags)
        for i, b in enumerate(data):
            buffer[i] = b
        return len(data)

    def recv(self, buflen=1042, flags=0):
        """Receive up to buflen bytes.
        The received full cipher blocks are decrypted and returned and partial cipher blocks are buffered locally.
        """
        assert not flags and buflen > self.LENGTH_LENGTH

        result = b""

        while buflen > 1:
            if self.curr_in_block is None:
                if buflen < self.LENGTH_LENGTH:
                    return result

                block_length_bytes = self.socket.recv(self.LENGTH_LENGTH)
                if not block_length_bytes:
                    return result

                assert len(block_length_bytes) == self.LENGTH_LENGTH

                self.curr_in_total = \
                    struct.unpack("H", block_length_bytes)[0] + 16
                self.num_in_recv = 0
                self.curr_in_block = b""
                buflen -= self.LENGTH_LENGTH
            else:
                part = self.socket.recv(min(buflen,
                                            self.curr_in_total - self.num_in_recv))
                actual_len = len(part)
                self.curr_in_block += part
                buflen -= actual_len
                self.num_in_recv += actual_len

                if self.num_in_recv == self.curr_in_total:
                    nonce = struct.pack("Q", self.in_count).rjust(12, b"\x00")

                    block_length = self.curr_in_total - 16
                    in_cipher = ChaCha20_Poly1305.new(key=self.incoming_key, nonce=nonce)
                    in_cipher.update(struct.pack("H", block_length))
                    dec = in_cipher.decrypt_and_verify(self.curr_in_block[:-16], self.curr_in_block[-16:])
                    result += dec
                    self.in_count += 1
                    self.curr_in_block = None
                    break

        return result

    @_with_out_lock
    def send(self, data, flags=0):
        """Encrypt and send the given data."""
        return self.sendall(data, flags)

    @_with_out_lock
    def sendall(self, data, flags=0):
        """Encrypt and send the given data."""
        assert not flags
        result = b""
        offset = 0
        total = len(data)
        while offset < total:
            length = min(total - offset, self.MAX_BLOCK_LENGTH)
            length_bytes = struct.pack("H", length)
            block = bytearray(data[offset: offset + length])
            nonce = struct.pack("Q", self.out_count).rjust(12, b"\x00")

            out_cipher = ChaCha20_Poly1305.new(key=self.outgoing_key, nonce=nonce)
            out_cipher.update(struct.pack("H", length))
            enc, tag = out_cipher.encrypt_and_digest(block)
            ciphertext = length_bytes + enc + tag
            offset += length
            self.out_count += 1
            result += ciphertext
        self.socket.sendall(result)
        return total
