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
    #connection = None

    def __init__(self, host, port):
        self.connection = RTSPConnection2(host, port)


    def parse_request(self):
        self.raw_requestline = self.raw_requestline.replace(b"RTSP/1.0", b"HTTP/1.1")

        r = http.server.BaseHTTPRequestHandler.parse_request(self)
        self.protocol_version = "RTSP/1.0"
        self.close_connection = 0
        return r

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

    def do_GET(self):
        print(self.headers)
        if self.path == "/info":
            print("GET /info")
            self.handle_info()
        else:
            print("GET %s Not implemented!" % self.path)
            self.send_error(404)

    def do_SETUP(self):
        dacp_id = self.headers.get("DACP-ID")
        active_remote = self.headers.get("Active-Remote")
        ua = self.headers.get("User-Agent")
        print("SETUP %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
                if "streams" not in plist:
                    print("Sending EVENT:")
                    event_port, self.event_proc = Event.spawn()
                    sonos_one_setup["eventPort"] = event_port
                    print("[+] eventPort=%d" % event_port)

                    self.pp.pprint(sonos_one_setup)
                    res = writePlistToString(sonos_one_setup)
                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                else:
                    print("Sending CONTROL/DATA:")

                    stream = Stream(plist["streams"][0])
                    self.server.streams.append(stream)
                    sonos_one_setup_data["streams"][0]["controlPort"] = stream.control_port
                    sonos_one_setup_data["streams"][0]["dataPort"] = stream.data_port

                    print("[+] controlPort=%d dataPort=%d" % (stream.control_port, stream.data_port))
                    if stream.type == Stream.BUFFERED:
                        sonos_one_setup_data["streams"][0]["type"] = stream.type
                        sonos_one_setup_data["streams"][0]["audioBufferSize"] = 8388608

                    self.pp.pprint(sonos_one_setup_data)
                    res = writePlistToString(sonos_one_setup_data)

                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                return
        self.send_error(404)

    def do_GET_PARAMETER(self):
        print("GET_PARAMETER %s" % self.path)
        print(self.headers)
        params_res = {}
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            params = body.splitlines()
            for p in params:
                if p == b"volume":
                    print("GET_PARAMETER: %s" % p)
                    params_res[p] = str(get_volume()).encode()
                else:
                    print("Ops GET_PARAMETER: %s" % p)

        res = b"\r\n".join(b"%s: %s" % (k, v) for k, v in params_res.items()) + b"\r\n"
        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_PARAM)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

    def do_SET_PARAMETER(self):
        print("SET_PARAMETER %s" % self.path)
        print(self.headers)
        params_res = {}
        content_type = self.headers["Content-Type"]
        content_len = int(self.headers["Content-Length"])
        if content_type == HTTP_CT_PARAM:
            if content_len > 0:
                body = self.rfile.read(content_len)

                params = body.splitlines()
                for p in params:
                    pp = p.split(b":")
                    if pp[0] == b"volume":
                        print("SET_PARAMETER: %s => %s" % (pp[0], pp[1]))
                        set_volume(float(pp[1]))
                    elif pp[0] == b"progress":
                        print("SET_PARAMETER: %s => %s" % (pp[0], pp[1]))
                    else:
                        print("Ops SET_PARAMETER: %s" % p)
        elif content_type == HTTP_CT_IMAGE:
            if content_len > 0:
                fname = None
                with tempfile.NamedTemporaryFile(prefix="artwork", dir=".", delete=False) as f:
                    f.write(self.rfile.read(content_len))
                    fname = f.name
                print("Artwork saved to %s" % fname)
        elif content_type == HTTP_CT_DMAP:
            if content_len > 0:
                self.rfile.read(content_len)
                print("Now plaing DAAP info. (need a daap parser here)")
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        print("RECORD %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETRATEANCHORTIME(self):
        print("SETRATEANCHORTIME %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_TEARDOWN(self):
        print("TEARDOWN %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                if "streams" in plist:
                    stream_id = plist["streams"][0]["streamID"]
                    stream = self.server.streams[stream_id]
                    stream.teardown()
                    del self.server.streams[stream_id]
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETPEERS(self):
        print("SETPEERS %s" % self.path)
        print(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_FLUSH(self):
        print("FLUSH %s" % self.path)
        print(self.headers)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_command(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                newin = []
                if "mrSupportedCommandsFromSender" in plist["params"]:
                    for p in plist["params"]["mrSupportedCommandsFromSender"]:
                        iplist = readPlistFromString(p)
                        newin.append(iplist)
                    plist["params"]["mrSupportedCommandsFromSender"] = newin
                if "params" in plist["params"] and "kMRMediaRemoteNowPlayingInfoArtworkData" in plist["params"][
                    "params"]:
                    plist["params"]["params"]["kMRMediaRemoteNowPlayingInfoArtworkData"] = "<redacted ..too long>"
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_feedback(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_audiomode(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_auth_setup(self):
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            hexdump(body)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_fp_setup(self):
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            hexdump(body)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_auth_setup(self):
        self.connection.putrequest("POST", "/auth-setup", False, False)
        #self.connection.putheader("Content-Length")
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

            #if res.status == 200:
            data = res.read()
            hexdump(data)
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

    def upgrade_to_encrypted(self, shared_key):
        self.request = self.server.upgrade_to_encrypted(
            self.client_address,
            shared_key)
        self.connection = self.request
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb')
        self.is_encrypted = True
        print("----- ENCRYPTED CHANNEL -----")


def get_free_port():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port


class AP2Server(socketserver.TCPServer):

    def __init__(self, addr_port, handler):
        super().__init__(addr_port, handler)
        self.connections = {}
        self.hap = None
        self.enc_layer = False
        self.streams = []

    # Override
    def get_request(self):
        client_socket, client_addr = super().get_request()
        print("Got connection with %s:%d" % client_addr)
        self.connections[client_addr] = client_socket
        return (client_socket, client_addr)

    def upgrade_to_encrypted(self, client_address, shared_key):
        client_socket = self.connections[client_address]
        hap_socket = HAPSocket(client_socket, shared_key)
        self.connections[client_address] = hap_socket
        return hap_socket


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