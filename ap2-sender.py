import os
import sys
import time
import struct
import socket
import argparse
import tempfile
import multiprocessing

import pprint

import http.server
import http.client
import socketserver

import netifaces as ni
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from hexdump import hexdump
from Crypto.Cipher import ChaCha20_Poly1305, AES
from zeroconf import IPVersion, ServiceInfo, Zeroconf
from biplist import readPlistFromString, writePlistToString, readPlist

from ap2.pairing import srp
from ap2.utils import get_volume, set_volume
from ap2.pairing.hap import HAPSocket, HapClient, Hap, Tlv8, PairingMethod
from ap2.connections.event import Event
from ap2.connections.stream import Stream
from ap2.rtsp_client import RTSPConnection
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from ap2.pairing import srp
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA1
from OpenSSL import crypto

DEVICE_ID = None
IPV4 = None
IPV6 = None

CLIENT_VERSION = "409.16.81"
HTTP_CT_BPLIST = "application/x-apple-binary-plist"
HTTP_CT_OCTET = "application/octet-stream"
HTTP_CT_PARAM = "text/parameters"
HTTP_CT_IMAGE = "image/jpeg"
HTTP_CT_DMAP = "application/x-dmap-tagged"

def setup_global_structs(args):
    global sonos_one_info
    global sonos_one_setup
    global sonos_one_setup_data
    global second_stage_info
    global mdns_props

    second_stage_info = {
        "initialVolume": get_volume(),
    }

    sonos_one_setup = {
        'eventPort': 0,  # AP2 receiver event server
        'timingPort': 0,
        'timingPeerInfo': {
            'Addresses': [
                IPV4, IPV6],
            'ID': IPV4}
    }

    sonos_one_setup_data = {
        'streams': [
            {
                'type': 96,
                'dataPort': 0,  # AP2 receiver data server
                'controlPort': 0  # AP2 receiver control server
            }
        ]
    }

class AP2Client():
    pp = pprint.PrettyPrinter()

    def __init__(self, host, port):
        self.connection = RTSPConnection(host, port)
        self.connection.hap = None

    def upgrade_to_encrypted(self, shared_key):
        hap_socket = HAPSocket(self.connection.sock, shared_key, HAPSocket.SocketType.ACCESSORY)
        self.connection.sock = hap_socket
        # self.connection.fp = self.connection.sock.makefile('rb')

        self.is_encrypted = True
        print("----- ENCRYPTED CHANNEL -----")

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = b''

        response = "%s %d %s\r\n" % (self.protocol_version, code, message)
        self.wfile.write(response.encode())

    def version_string(self):
        return "AirPlay/%s" % CLIENT_VERSION

    def do_info(self):
        plist_info = { 'qualifier': ['txtAirPlay'] }
        plist_info_bin = writePlistToString(plist_info, True)

        self.connection.putrequest("GET", "/info", False, False)
        self.connection.putheader("CSeq", 1)
        self.connection.putheader("Content-Length", len(plist_info_bin))
        self.connection.putheader("Content-Type", HTTP_CT_BPLIST)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.endheaders()
        self.connection.send(plist_info_bin)

        res = self.connection.getresponse()

        if res.status == 200:
            data = res.read()
            hexdump(data)
            print("----- INFO -----")
            self.dumpPlist(data)

    def do_pairpinstart(self):
        print("----- PAIR-PIN-START -----")

        self.connection.putrequest("POST", "/pair-pin-start", False, False)
        self.connection.putheader("CSeq", 1)
        self.connection.putheader("Content-Type", HTTP_CT_BPLIST)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.endheaders()
        # self.connection.send()

        res = self.connection.getresponse()

        if res.status == 200:
            print("----- PAIR-PIN-START OK -----")


    def do_auth_setup(self):
        self.connection.putrequest("POST", "/auth-setup", False, False)
        self.connection.putheader("CSeq", 1)
        self.connection.putheader("Content-Length", 33)
        self.connection.putheader("Content-Type", HTTP_CT_BPLIST)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.putheader("X-Apple-HKP", 4)
        self.connection.endheaders()

        encryption_type = b'\x01'
        accessory_curve = x25519.X25519PrivateKey.generate()
        client_curve25519_pk = accessory_curve.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        body = encryption_type + client_curve25519_pk
        self.connection.send(body)

        res = self.connection.getresponse()
        print("----- AUTH SETUP RESPONSE -----")

        print(res.headers)
        if res.status == 200:
            data = res.read()
            hexdump(data)

            server_curve25519_pk = data[0:32]
            accessory_shared_key = accessory_curve.exchange(
                x25519.X25519PublicKey.from_public_bytes(server_curve25519_pk))

            cert_length = struct.unpack(">I", data[32:36])[0]
            cert = data[36:36+cert_length]
            sig_length = struct.unpack(">I", data[36+cert_length:40+cert_length])[0]
            sig = data[40+cert_length:]

            message_to_check_digest = SHA1.new()
            message_to_check_digest.update(server_curve25519_pk)
            message_to_check_digest.update(client_curve25519_pk)

            digest = SHA1.new()
            digest.update(b"AES-KEY")
            digest.update(accessory_shared_key)
            aes_master_key = digest.digest()[0:16]

            digest = SHA1.new()
            digest.update(b"AES-IV")
            digest.update(accessory_shared_key)
            aes_master_iv = digest.digest()[0:16]

            ctr = Counter.new(nbits=128, initial_value=srp.from_bytes(aes_master_iv, False))
            print(hexdump(aes_master_iv))
            ctr.update()
            aes = AES.new(aes_master_key, AES.MODE_CTR, counter=ctr)
            sig = aes.decrypt(sig)

            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, cert)
            certs = get_certificates(pkcs7)

            for cert in certs:
                rsapubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())

            rsakey = RSA.importKey(rsapubkey)
            signer = PKCS1_v1_5.new(rsakey)

            if signer.verify(message_to_check_digest, sig):
                print("----- AUTH SETUP SIGNATURE OK  -----")
                return True
        else:
            print("----- AUTH SETUP RESPONSE ERROR OCCURED -----")

    def do_pairing(self, pin_challenged=False):
        if not self.connection.hap:
            self.connection.hap = HapClient(self.handle_pairing_callback)

        self.connection.hap.do_pairing(pin_challenged)

    def handle_pairing_callback(self, req, pairing_status):
        if pairing_status.encrypted:
            self.upgrade_to_encrypted(self.connection.hap.shared_key)

        if pairing_status.global_status == "PAIRED":
            return

        if pairing_status.method == PairingMethod.PAIR_SETUP \
                or pairing_status.method == PairingMethod.PAIR_SETUP_AUTH:
            path = "/pair-setup"

        self.connection.putrequest("POST", path, False, False)
        self.connection.putheader("CSeq", 2)
        self.connection.putheader("Content-Length", len(req))
        self.connection.putheader("Content-Type", HTTP_CT_BPLIST)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.putheader("X-Apple-HKP", 4)

        self.connection.endheaders()
        self.connection.send(req)

        res = self.connection.getresponse()

        if res.status == 200:
            data = res.read()
            hexdump(data)

            return data

        return res

    def list_pairings(self):
        if not self.connection or (self.connection and not self.connection.hap):
            print("Previous pairing is required")
            return

        req = self.connection.hap.list_pairings()
        self.connection.putrequest("POST", "/pair-setup", False, False)
        self.connection.putheader("Content-Length", len(req))
        self.connection.putheader("Content-Type", HTTP_CT_BPLIST)
        self.connection.putheader("CSeq", 1)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.putheader("X-Apple-HKP", 4)
        self.connection.endheaders()
        self.connection.send(req)
        res = self.connection.getresponse()
        if res.status == 200:
            data = res.read()
            hexdump(data)

            return data

    def dumpPlist(self, plistData):
        plist = readPlistFromString(plistData)
        self.pp.pprint(plist)

def get_free_port():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port

def get_certificates(self):
    from OpenSSL.crypto import _lib, _ffi, X509
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509()
        # pycert._x509 = _lib.sk_X509_value(certs, i)
        # According to comment from @ Jari Turkia
        # to prevent segfaults use '_lib.X509_dup('
        pycert._x509 = _lib.X509_dup(_lib.sk_X509_value(certs, i))
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)

if __name__ == "__main__":

    try:
        HOST = "192.168.28.2"
        PORT = 7000
        monclient = AP2Client(HOST, PORT)
        monclient.do_pairpinstart()
        monclient.do_pairing(True)
        monclient.do_info()
        auth_setup_ok = monclient.do_auth_setup()

    except KeyboardInterrupt:
        pass
    finally:
        print ("Done")