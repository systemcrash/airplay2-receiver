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
from hexdump import hexdump
from Crypto.Cipher import ChaCha20_Poly1305, AES
from zeroconf import IPVersion, ServiceInfo, Zeroconf
from biplist import readPlistFromString, writePlistToString

from ap2.pairing import srp
from ap2.utils import get_volume, set_volume
from ap2.pairing.hap import HAPSocket, HapClient, Hap, Tlv8
from ap2.connections.event import Event
from ap2.connections.stream import Stream
from ap2.rtsp_client import RTSPConnection

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

class RTSPConnection2(RTSPConnection):
    def parse_request(self):
        print ("toto")

    def __init__(self, host, port):
        super(RTSPConnection2, self).__init__(host, port)
        self.hap = None

class AP2Client():
    pp = pprint.PrettyPrinter()

    def __init__(self, host, port):
        self.connection = RTSPConnection2(host, port)

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
        self.connection.putrequest("GET", "/info", False, False)
        self.connection.putheader("CSeq", 1)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.endheaders()

    def do_auth_setup(self):
        self.connection.putrequest("POST", "/auth-setup", False, False)
        self.connection.putheader("CSeq", 1)
        self.connection.putheader("Content-Length", 33)
        self.connection.putheader("Content-Type", HTTP_CT_BPLIST)
        self.connection.putheader("User-Agent", self.version_string())
        self.connection.putheader("X-Apple-HKP", 4)
        self.connection.endheaders()

        body = b'\x01\x4E\xEA\xD0\x4E\xA9\x2E\x47\x69\xD2\xE1\xFB\xD0\x96\x81\xD5\x94\xA8\xEF\x18\x45\x4A\x24\xAE\xAF\xB3\x14\x97\x0D\xA0\xB5\xA3\x49'
        self.connection.send(body)

        res = self.connection.getresponse()

        if res.status == 200:
            data = res.read()
            hexdump(data)


    def do_pair_setup(self):
        if not self.connection.hap:
            self.connection.hap = HapClient()
        req = self.connection.hap.pair_setup_m1()

        self.connection.putrequest("POST", "/pair-setup", False, False)
        #self.connection.putheader("Content-Length")
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
            req = self.connection.hap.pair_setup_m2_m3(data)
            self.connection.putrequest("POST", "/pair-setup", False, False)
            self.connection.putheader("CSeq", 3)
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
                self.connection.hap.pair_setup_m4(data)
                print("Shared Key")
                hexdump(self.connection.hap.shared_key)
                self.upgrade_to_encrypted(self.connection.hap.shared_key)
                self.do_info()
                res = self.connection.getresponse()

        return res

    def handle_pair_verify(self):
        content_len = int(self.headers["Content-Length"])

        body = self.rfile.read(content_len)

        if not self.server.hap:
            self.server.hap = Hap()
        res = self.server.hap.pair_verify(body)

        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_OCTET)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

        if self.server.hap.encrypted:
            hexdump(self.server.hap.accessory_shared_key)
            self.upgrade_to_encrypted(self.server.hap.accessory_shared_key)

    def handle_info(self):
        if "Content-Type" in self.headers:
            if self.headers["Content-Type"] == HTTP_CT_BPLIST:
                content_len = int(self.headers["Content-Length"])
                if content_len > 0:
                    body = self.rfile.read(content_len)

                    plist = readPlistFromString(body)
                    self.pp.pprint(plist)
                    if "qualifier" in plist and "txtAirPlay" in plist["qualifier"]:
                        print("Sending:")
                        self.pp.pprint(sonos_one_info)
                        res = writePlistToString(sonos_one_info)

                        self.send_response(200)
                        self.send_header("Content-Length", len(res))
                        self.send_header("Content-Type", HTTP_CT_BPLIST)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                        self.wfile.write(res)
                    else:
                        print("No txtAirPlay")
                        self.send_error(404)
                        return
                else:
                    print("No content")
                    self.send_error(404)
                    return
            else:
                print("Content-Type: %s | Not implemented" % self.headers["Content-Type"])
                self.send_error(404)
        else:
            res = writePlistToString(second_stage_info)
            self.send_response(200)
            self.send_header("Content-Length", len(res))
            self.send_header("Content-Type", HTTP_CT_BPLIST)
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            self.wfile.write(res)

def get_free_port():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port


if __name__ == "__main__":

    try:
        HOST = "192.168.28.163"
        PORT = 7000

        # hapServer = Hap()
        # hapClient = HapClient()
        # tlvServer = hapServer.pair_setup_m1_m2()
        #
        # serverKey = tlvServer[Tlv8.Tag.PUBLICKEY]
        # salt = tlvServer[Tlv8.Tag.SALT]
        # tlvClient = Tlv8.decode(hapClient.pair_setup_m2_m3(Tlv8.encode(tlvServer)))
        # hapServer.pair_setup_m3_m4(tlvClient[Tlv8.Tag.PUBLICKEY], tlvClient[Tlv8.Tag.PROOF])


        monclient = AP2Client(HOST, PORT)
        #monclient.do_auth_setup()
        res = monclient.do_pair_setup()
        # if res.status==200:


        # with AP2Client(HOST, PORT) as client:
        #    print("Connection to client", HOST, ":", PORT)
        #    client.do_pair_setup()
    except KeyboardInterrupt:
        pass
    finally:
        print ("Done")