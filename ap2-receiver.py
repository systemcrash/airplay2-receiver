import os
import sys
import time
import struct
import socket
import logging
import argparse
import tempfile
import multiprocessing
import random
import threading
from threading import current_thread

import pprint

import http.server
import socketserver
import asyncio

import netifaces as ni
from hexdump import hexdump
from zeroconf import IPVersion, ServiceInfo, Zeroconf, NonUniqueNameException
from biplist import readPlistFromString, writePlistToString
from biplist import InvalidPlistException, NotBinaryPlistException

from ap2.playfair import PlayFair, FairPlayAES
from ap2.airplay1 import AP1Security
from ap2.utils import get_volume, set_volume, set_volume_pid, get_screen_logger
from ap2.pairing.hap import Hap, HAPSocket, LTPK, DeviceProperties
from ap2.connections.event import EventGeneric
from ap2.connections.stream import Stream
from ap2.connections.session_properties import Session
from ap2.dxxp import parse_dxxp
from ap2.bitflags import FeatureFlags, StatusFlags
from ap2.sdphandler import SDPHandler
from ap2.mediaremotecommands import MediaCommandParser, MRNowPlayingInfo

FEATURES = FeatureFlags.GetDefaultAirplayTwoFlags(FeatureFlags)
STATUS_FLAGS = StatusFlags.GetDefaultStatusFlags(StatusFlags)

# PI = Public ID (can be GUID, MAC, some string).
#  Note: BINARY. HAP classes expect binary format. Must be in text in device_info.
PI = b'aa5cb8df-7f14-4249-901a-5e748ce57a93'
GROUP_UUID = None  # '5dccfd20-b166-49cc-a593-6abd5f724ddb'
GCGL = False
IS_GROUP_LEADER = False
SESSION = None
SENDER_ADDR = None
STREAMS = []
STREAM_ID = 0
DEBUG = False

# The device MAC - string form.
DEVICE_ID = None
# HAP object to hold device properties like name, ACL, password etc.
DEV_PROPS = None
# The chosen interface's IPv4/6
IPV4 = None
IPV6 = None
IPADDR = None
# Globally assign the device name provided from the command line
DEV_NAME = None
# Object to hold our mDNS broadcaster
MDNS_OBJ = None
# HomeKit AccessControl level to persist settings we get from HomeKit
#  0=Everyone, 1=(HomeKit Users), 2=Admin
HK_ACL_LEVEL = 0
# HomeKit assigned password (numeric PIN) to access
HK_PW = None

"""
# SERVER_VERSION; presence/absence, and value dictates client behaviours
Set above 360 to trigger remote control
Set to <= 355 to trigger REALTIME and NTP (as opposed to buffered streams)
Set to >= 355 to trigger PTP and buffered.
Set to <= 350 to prevent shk in streams.
Set to 300 to trigger ??
Set to 200 to trigger ANNOUNCE (APv1)
"""
SERVER_VERSION = "366.0"
HTTP_CT_BPLIST = "application/x-apple-binary-plist"
HTTP_CT_OCTET = "application/octet-stream"
HTTP_CT_PARAM = "text/parameters"
HTTP_CT_IMAGE_JPEG = "image/jpeg"
HTTP_CT_IMAGE = "image/"
HTTP_CT_DMAP = "application/x-dmap-tagged"
HTTP_CT_PAIR = "application/pairing+tlv8"
"""
X-Apple-HKP:
Values 0,2,3,4,6 seen.
 0 = Unauth. When Ft48TransientPairing and Ft43SystemPairing are absent
 2 = (pair-setup complete, pair-verify starts)
 3 = SystemPairing (with Ft43SystemPairing)
 4 = Transient
 6 = HomeKit
 7 = HomeKit (administration)
"""
HTTP_X_A_HKP = "X-Apple-HKP"
HTTP_X_A_CN = "X-Apple-Client-Name"
HTTP_X_A_PD = "X-Apple-PD"
# HTTP_X_A_AT: Unix timestamp for current system date/time.
HTTP_X_A_AT = "X-Apple-AbsoluteTime"
# Encryption Type
HTTP_X_A_ET = "X-Apple-ET"

#
AIRPLAY_BUFFER = 8388608  # 0x800000 i.e. 1024 * 8192 - how many CODEC frame size 1024 we can hold


def increase_stream_id():
    global STREAM_ID
    STREAM_ID += 1
    # ID shall not exceed 32 bits.
    STREAM_ID &= 0xFFFFFFFF
    return STREAM_ID


def get_hex_bitmask(in_features):
    """
    prepares the feature bits into text form
    """
    if in_features.bit_length() <= 32:
        # print(f"{hex(in_features)}")
        return f"{hex(in_features)}"
    else:
        # print(f'feature bit length: {in_features.bit_length()} ')
        # print(f"{hex(in_features & 0xffffffff)},{hex(in_features >> 32 & 0xffffffff)}")
        return f"{hex(in_features & 0xffffffff)},{hex(in_features >> 32 & 0xffffffff)}"


def update_status_flags(flag=None, on=False, push=True):
    global MDNS_OBJ
    """ Use this to check for and send out updated status flags
    if flag is None, skip changing the flags (e.g. updates already queued)
    if on is true, add the flag in, otherwise remove it.
    if push is False, skip the update (e.g. you want to queue multiple changes)
    """
    if flag:
        global STATUS_FLAGS
        # If the flag is not present in STATUS_FLAGS, add it in, if on is True
        if not STATUS_FLAGS & flag and on:
            STATUS_FLAGS ^= flag
        elif STATUS_FLAGS & flag and not on:
            STATUS_FLAGS ^= flag
    # update the global info structures
    setup_global_structs(args, isDebug=DEBUG)
    # If push is false, we skip pushing out the update.
    if push:
        MDNS_OBJ = register_mdns(DEVICE_ID, DEV_NAME, [IP4ADDR_BIN, IP6ADDR_BIN])


def setup_global_structs(args, isDebug=False):
    global device_info
    global device_setup
    global stream_setup_data
    global second_stage_info
    global mdns_props
    global LTPK_OBJ
    global DEV_NAME
    LTPK_OBJ = LTPK(PI, isDebug)

    device_info = {
        # 'OSInfo': 'Linux 3.10.53',
        # 'PTPInfo': 'OpenAVNU ArtAndLogic-aPTP-changes a5d7f94-0.0.1',
        'audioLatencies': [
            {
                # audioType can be: e.g. NULL/nothing (iTunes), default, media, telephony, speechRecognition, alert
                #  (AP1?) GeneralAudio(96), MainAudio(100), AltAudio(101), Screen(110).
                #  Absence triggers default.
                # 'audioType': 'default',
                'inputLatencyMicros': 0,
                'outputLatencyMicros': 400000,
                # Type can be any RTP type, 96, 100, 103, 110 etc.
                # 'type': 96
            },
        ],
        # 'build': '16.0',
        'deviceID': DEVICE_ID,
        # features: can send in hex() also
        'features': int(FEATURES),
        # 'features': 496155769145856, # Sonos One
        # 'firmwareBuildDate': 'Nov  5 2019',
        # 'firmwareRevision': '53.3-71050',
        # 'hardwareRevision': '1.21.1.8-2',
        # 'initialVolume': -144.0,
        'keepAliveLowPower': True,
        'keepAliveSendStatsAsBody': True,
        'manufacturer': 'OpenAirplay',
        'model': 'Receiver',
        'name': DEV_NAME,
        'nameIsFactoryDefault': False,
        'pi': PI.decode(),  # UUID generated casually..
        # 'psi': PI.decode(),  # ?
        'protocolVersion': '1.1',
        'sdk': 'AirPlay;2.0.2',
        'sourceVersion': SERVER_VERSION,
        'statusFlags': get_hex_bitmask(STATUS_FLAGS),
        # 'supportedFormats': {
        #     'lowLatencyAudioStream': 0,
        #     # 'screenStream': 21235712,
        #     'audioStream': 21235712,
        #     'bufferStream': 14680064,
        # },
        # 'statusFlags': 0x404 # Sonos One
        # 'volumeControlType': 4,  # 1-4 all seem to behave the same.
        # 'vv': 2,
    }

    if DISABLE_VM:
        volume = 0
    else:
        volume = get_volume()
    second_stage_info = {
        "initialVolume": volume,
    }

    device_setup = {
        'eventPort': 0  # AP2 receiver event server
    }
    if not DISABLE_PTP_MASTER:
        if IPV6 and not IPV4:
            addr = [
                IPV6
            ]
        else:
            # Prefer (only) IPV4
            addr = [
                IPV4
            ]
        device_setup['timingPort'] = 0  # Seems like legacy, non PTP setting
        device_setup['timingPeerInfo'] = {
            'Addresses': addr,
            'ID': DEVICE_ID
        }

    stream_setup_data = {
        'streams': [
        ]
    }

    mdns_props = {
        # Airplay flags
        # Access ControL. 0,1,2 == anon,users,admin(?)
        "acl": HK_ACL_LEVEL,
        "deviceid": DEVICE_ID,  # device MAC addr
        # Features, aka ft - see Feat class.
        "features": get_hex_bitmask(FEATURES),
        # flags (bitmask)
        "flags": get_hex_bitmask(STATUS_FLAGS),
        # Group Contains Group Leader.
        # "gcgl": "0",
        # Group UUID (generated casually)
        # "gid": "5dccfd20-b166-49cc-a593-6abd5f724ddb",
        # isGroupLeader: See gcgl
        # "isGroupLeader": "0",
        "manufacturer": "OpenAirplay",
        "model": "Airplay2-Receiver",
        "name": DEV_NAME,
        "protovers": "1.1",
        # Required Sender Features (bitmask)
        "rsf": "0x0",
        "serialNumber": DEVICE_ID,
        # Source Version (airplay SDK?): absence triggers AP1 ANNOUNCE behaviour.
        "srcvers": SERVER_VERSION,

        # RAOP Flags - ("xx") - mostly used with RAOP
        # These are found under the <deviceid>@<name> mDNS record.
        # Apple Model (name)
        # "am": "One",
        # (amount of audio) CHannels
        "ch": "2",
        # CompressioN. 0,1,2,3 == (None aka) PCM, ALAC, AAC, AAC_ELD
        "cn": "0,1,2",
        # Digest Auth RFC-2617 support
        # "da": "true",
        # Encryption Key
        # "ek": "1",
        # Encryption Types. 0,1,3,4,5 == None, RSA, FairPlay, Mfi, FairPlay SAPv2.5
        # "et": "0,1,3",
        # "et": "0,1,3,4,5",
        # Firmware version. p20 == AirPlay Src revision?
        # "fv": "p20.78000.12",
        # MetaData(?) 0,1,2 == Text, Gfx, Progress (only needed for pre iOS7 senders)
        # "md": "0,1,2",
        # Pairing UUID (generated casually)
        "pi": PI.decode(),
        # Ed25519 PubKey
        "pk": LTPK_OBJ.get_pub_string(),
        # "protovers": "1.1",
        # PassWord enabled: 0/false off, 1/true on.
        # -This requires Method POST Path /pair-pin-start endpoint
        # "pw": "false",
        # Status Flags (bitmask): see StatusFlags class.
        "sf": get_hex_bitmask(STATUS_FLAGS),
        # Software Mute (whether needed)
        # "sm": "false",
        # Sample Rate
        # "sr": "44100",
        # Sample Size
        # "ss": "16",
        # Software Volume (whether needed)
        # "sv": "false",
        # TransPort for media. CSV of capables transports for audio
        # "tp": "TCP,UDP",
        # (Airplay) version number (supported) 16bit.16bit, 65537 == 1.1
        # "vn": "65537",
        # Source version
        # "vs": "366",
    }
    """ Remotes only react to the presence of the gid flag. How remotes
    react to UUID(s) in the tag is <undefined> """
    print(f'GROUP_UUID: {GROUP_UUID}')
    if GROUP_UUID:
        print('appending GROUP_UUID')
        mdns_props['gid'] = GROUP_UUID
        mdns_props['gcgl'] = '1' if GCGL else '0'
        mdns_props['isGroupleader'] = '1' if IS_GROUP_LEADER else '0'
        if SENDER_ADDR:
            print('appending SENDER_ADDR to device_info')
            device_info['senderAddress'] = SENDER_ADDR
        else:
            if 'senderAddress' in device_info:
                del device_info['senderAddress']
    else:
        if 'gid' in mdns_props:
            del mdns_props['gid']
        if 'gcgl' in mdns_props:
            del mdns_props['gcgl']
        if 'isGroupleader' in mdns_props:
            del mdns_props['isGroupleader']


class AP2Handler(http.server.BaseHTTPRequestHandler):
    aeskeyobj = None
    pp = pprint.PrettyPrinter()
    timing_port, ptp_port = 0, 0
    timing_proc, ptp_proc = None, None
    fairplay_keymsg = None
    ecdh_shared_key = None
    session = None
    hap = None

    # Maps paths to methods a la HAP-python
    HANDLERS = {
        "POST": {
            "/command": "handle_command",
            "/feedback": "handle_feedback",
            "/audioMode": "handle_audiomode",
            "/auth-setup": "handle_auth_setup",
            "/fp-setup": "handle_fp_setup",
            "/fp-setup2": "handle_auth_setup",
            "/pair-setup": "handle_pair_setup",
            "/pair-verify": "handle_pair_verify",
            "/pair-add": "handle_pair_add",
            "/pair-remove": "handle_pair_remove",
            "/pair-list": "handle_pair_list",
            "/configure": "handle_configure",
        },
        "GET": {
            "/info": "handle_info",
        },
        "PUT": {"/xyz": "handle_xyz"},
    }

    """ This is needed now to prep logging in case we get a sneak attack from
    AP1 senders that don't go via dispatch """
    def __init__(self, socket, client_address, server):
        """ thread local logging """
        server_address = socket.getsockname()
        pair_string = f'{self.__class__.__name__}: {server_address[0]}:{server_address[1]}<=>{client_address[0]}:{client_address[1]}'
        pair_string += f'; {current_thread().name}'
        level = 'DEBUG' if DEBUG else 'INFO'
        self.logger = get_screen_logger(pair_string, level=level)
        http.server.BaseHTTPRequestHandler.__init__(self, socket, client_address, server)
        return

    def dispatch(self):
        """Dispatch the request to the appropriate handler method."""
        path = self.path
        paramStr = ''
        if '?' in self.path:
            path = self.path.split('?')[0]
            paramStr = self.path.split('?')[1]

        self.logger.debug(f'{self.command}: {path}')
        self.logger.debug(f'!Dropped parameters: {paramStr}') if paramStr else self.logger.debug('')
        self.logger.debug(self.headers)
        try:
            # pass additional paramArray:
            # getattr(self, self.HANDLERS[self.command][path])(paramArray)
            # Note: handle_* signatures need e.g. (self, *args, **kwargs)
            getattr(self, self.HANDLERS[self.command][path])()
        except KeyError:
            self.send_error(
                404,
                f": Method {self.command} Path {path} endpoint not implemented"
            )
            self.hap = None

    def parse_request(self):
        self.raw_requestline = self.raw_requestline.replace(b"RTSP/1.0", b"HTTP/1.1")

        r = http.server.BaseHTTPRequestHandler.parse_request(self)
        self.protocol_version = "RTSP/1.0"
        self.close_connection = 0
        return r

    def process_info(self, device_name):
        self.logger.info('Process info called')
        device_info["name"] = "TODO"

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = b''

        response = f"{self.protocol_version} {code} {message}\r\n"
        self.wfile.write(response.encode())

    def version_string(self):
        return f"AirTunes/{SERVER_VERSION}"

    def do_GET(self):
        self.dispatch()

    def do_OPTIONS(self):
        self.logger.debug(self.headers)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])

        if "Apple-Challenge" in self.headers:
            # Build Apple-Reponse
            apple_response = AP1Security.compute_apple_response(self.headers["Apple-Challenge"], IPADDR_BIN, DEVICE_ID_BIN)
            self.send_header("Apple-Jack-Status", "connected; type=analog")
            self.send_header("Apple-Response", apple_response)
        self.send_header("Public",
                         "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH"
                         "FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, PUT"
                         "SETPEERSX"
                         )
        self.end_headers()

    def do_ANNOUNCE(self):
        # Enable Feature bit 12: Ft12FPSAPv2p5_AES_GCM: this uses only RSA
        # Enabling Feat bit 25 and iTunes4win attempts AES - cannot yet decrypt.
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)

        if self.headers["Content-Type"] == 'application/sdp':
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                sdp_body = self.rfile.read(content_len).decode('utf-8')
                self.logger.debug(sdp_body)
                sdp = SDPHandler(sdp_body)
                self.aud_params = sdp.params
                if sdp.has_mfi:
                    self.logger.warning("MFi not possible on this hardware.")
                    self.send_response(404)
                    self.hap = None
                else:
                    if(sdp.audio_format is SDPHandler.SDPAudioFormat.ALAC
                       and int((FEATURES & FeatureFlags.getFeature19ALAC(FeatureFlags))) == 0):
                        self.logger.warning("This receiver not configured for ALAC (set flag 19).")
                        self.send_response(404)
                        self.hap = None
                    elif (sdp.audio_format is SDPHandler.SDPAudioFormat.AAC
                          and int((FEATURES & FeatureFlags.getFeature20AAC(FeatureFlags))) == 0):
                        self.logger.warning("This receiver not configured for AAC (set flag 20).")
                        self.send_response(404)
                        self.hap = None
                    elif (sdp.audio_format is SDPHandler.SDPAudioFormat.AAC_ELD
                          and int((FEATURES & FeatureFlags.getFeature20AAC(FeatureFlags))) == 0):
                        self.logger.warning("This receiver not configured for AAC (set flag 20/21).")
                        self.send_response(404)
                        self.hap = None
                    else:
                        if sdp.has_fp and self.fairplay_keymsg:
                            self.logger.debug('Got FP AES Key from SDP')
                            self.aeskeyobj = FairPlayAES(fpaeskeyb64=sdp.aeskey, aesivb64=sdp.aesiv, keymsg=self.fairplay_keymsg)
                        elif sdp.has_rsa:
                            self.aeskeyobj = FairPlayAES(rsaaeskeyb64=sdp.aeskey, aesivb64=sdp.aesiv)
                        self.send_response(200)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                self.sdp = sdp

    def do_FLUSHBUFFERED(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                fr = 0
                if "flushFromSeq" in plist:
                    fr = plist["flushFromSeq"]
                if "flushUntilSeq" in plist:
                    to = plist["flushUntilSeq"]
                    try:
                        for s in self.server.streams:
                            if s.isAudio() and s.isInitialized() and not s.isRCO():
                                s.getAudioConnection().send(f"flush_from_until_seq-{fr}-{to}")
                    except OSError as e:
                        self.logger.error(f'FLUSHBUFFERED error: {repr(e)}')
                        pass
                    except AttributeError as e:
                        pass

                self.logger.debug(self.pp.pformat(plist))

    def do_POST(self):
        self.dispatch()

    def do_SETUP(self):
        global GROUP_UUID, GCGL, IS_GROUP_LEADER
        global SENDER_ADDR
        global STREAMS
        dacp_id = self.headers.get("DACP-ID")
        active_remote = self.headers.get("Active-Remote")
        ua = self.headers.get("User-Agent")
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        # Found in SETUP after ANNOUNCE:
        if self.headers["Transport"]:
            # self.logger.debug(self.headers["Transport"])

            """ Run receiver with bit 13/14 and no bit 25, it's RSA in ANNOUNCE. Sender assumes you are an
            airport with only 250msec buffer, so min/max are absent from SDP. FP2 is a solution. """

            """ ct: 0x1 = PCM, 0x2 = ALAC, 0x4 = AAC_LC, 0x8 = AAC_ELD. largely implied by audioFormat """

            # Set up a stream to receive.
            stream = {
                'audioFormat': self.sdp.AirplayAudFmt,
                'latencyMin': int(self.sdp.audio_format_sr) // 4 if not self.sdp.minlatency else int(self.sdp.minlatency),
                'latencyMax': int(self.sdp.audio_format_sr) * 2 if not self.sdp.maxlatency else int(self.sdp.maxlatency),
                'ct': 0,  # Compression Type(?)
                'shk': self.aeskeyobj.aeskey,
                'shiv': self.aeskeyobj.aesiv,
                'spf': int(self.sdp.spf),  # sample frames per pkt
                'type': int(self.sdp.payload_type),
                'controlPort': 0,
            }

            streamobj = Stream(
                stream,
                IPADDR,
                buff_size=AIRPLAY_BUFFER,
                stream_id=increase_stream_id(),
                shared_key=self.ecdh_shared_key,
                isDebug=DEBUG,
                aud_params=self.aud_params
            )

            self.server.streams.append(streamobj)

            if not self.server.event_proc:
                self.server.event_port, self.server.event_proc = EventGeneric.spawn(
                    self.server.server_address, name='events', shared_key=self.ecdh_shared_key, isDebug=DEBUG)
            if not self.server.timing_proc:
                self.server.timing_port, self.server.timing_proc = EventGeneric.spawn(
                    self.server.server_address, name='ntp', shared_key=self.ecdh_shared_key, isDebug=DEBUG)
            transport = self.headers["Transport"].split(';')
            res = []
            res.append("RTP/AVP/UDP")
            res.append("unicast")
            res.append("mode=record")
            ctl_msg = f"control_port={streamobj.getControlPort()}"
            res.append(ctl_msg)
            self.logger.debug(ctl_msg)
            data_msg = f"server_port={streamobj.getDataPort()}"
            res.append(data_msg)
            self.logger.debug(data_msg)
            ntp_msg = f"timing_port={self.server.timing_port}"
            res.append(ntp_msg)
            self.logger.debug(ntp_msg)
            string = ';'

            self.send_response(200)
            self.send_header("Transport", string.join(res))
            self.send_header("Session", "1")
            self.send_header("Audio-Jack-Status", 'connected; type=analog')
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            self.logger.info('')
            # Send flag that we're active
            update_status_flags(StatusFlags.getRecvSessActive(StatusFlags), on=True)
            return

        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.logger.debug(self.pp.pformat(plist))

                if not self.session:
                    """ Only set up session first time at connection """
                    session = Session(plist, self.fairplay_keymsg)

                if session.getSessionUUID():
                    # The sessionUUID key determines whether this is a session.
                    self.server.sessions.append(session)
                    print(f'RCO?: {session.isRCO()}')
                    if session.getGroupUUID() and not session.isRCO():
                        GROUP_UUID = session.getGroupUUID()
                        GCGL = True  # session.gCGL()  # TODO: or True? :)
                        IS_GROUP_LEADER = True  # session.isGL()  # TODO: or true?
                        SENDER_ADDR = f'{self.client_address[0]}:{self.client_address[1]}'

                if "streams" not in plist:
                    self.logger.debug("Sending EVENT:")
                    self.server.event_port, self.server.event_proc = EventGeneric.spawn(
                        self.server.server_address, name='events', shared_key=self.ecdh_shared_key, isDebug=DEBUG)
                    device_setup["eventPort"] = self.server.event_port
                    self.logger.debug(f"[+] eventPort={self.server.event_port}")

                    self.logger.debug(self.pp.pformat(device_setup))
                    res = writePlistToString(device_setup)
                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                    self.logger.info('')
                else:
                    for stream in plist["streams"]:
                        s = Stream(
                            stream,
                            IPADDR,
                            buff_size=AIRPLAY_BUFFER,
                            stream_id=increase_stream_id(),
                            shared_key=self.ecdh_shared_key,
                            isDebug=DEBUG,
                        )
                        self.logger.debug("Building stream channels:")
                        self.server.streams.append(s)
                        stream_setup_data["streams"].append(
                            s.descriptor
                        )

                        self.logger.debug(s.getSummaryMessage())

                        if s.getStreamType() == Stream.BUFFERED:
                            set_volume_pid(s.getControlProc().pid)
                        if s.getStreamType() == Stream.REALTIME:
                            set_volume_pid(s.getControlProc().pid)

                    self.logger.debug(self.pp.pformat(stream_setup_data))
                    res = writePlistToString(stream_setup_data)

                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                    self.logger.info('')
                    # Set flag that we're active
                    update_status_flags(StatusFlags.getRecvSessActive(StatusFlags), on=True, push=False)
                # Push changes
                if not session.isRCO():
                    update_status_flags(push=True)
                return
        self.send_error(404)
        self.logger.info('')

    def do_GET_PARAMETER(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        params_res = {}
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            params = body.splitlines()
            for p in params:
                if p == b"volume":
                    self.logger.info(f"GET_PARAMETER: {p}")
                    if not DISABLE_VM:
                        params_res[p] = str(get_volume()).encode()
                    else:
                        self.logger.warning("Volume Management is disabled")
                else:
                    self.logger.info(f"Ops GET_PARAMETER: {p}")
        if DISABLE_VM:
            res = b"volume: 0" + b"\r\n"
        else:
            res = b"\r\n".join(b"%s: %s" % (k, v) for k, v in params_res.items()) + b"\r\n"
        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_PARAM)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)
        hexdump(res) if DEBUG else ''

    def do_SET_PARAMETER(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
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
                        self.logger.info(f"SET_PARAMETER: {pp[0]} => {pp[1]}")
                        if not DISABLE_VM:
                            set_volume(float(pp[1]))
                        else:
                            self.logger.warning("Volume Management is disabled")
                    elif pp[0] == b"progress":
                        # startTimeStamp, currentTimeStamp, stopTimeStamp
                        try:
                            for s in self.server.streams:
                                s.getAudioConnection().send(f"progress-{pp[1].decode('utf8').lstrip(' ')}")
                        except OSError as e:
                            self.logger.error(f'SET_PARAMETER error: {repr(e)}')
                        except AttributeError as e:
                            # Conn not ready yet
                            pass

                        self.logger.info(f"SET_PARAMETER: {pp[0]} => {pp[1]}")
                    # else:
                    #     self.logger.info(f"Ops SET_PARAMETER: {p}")

        elif content_type.startswith(HTTP_CT_IMAGE):
            if content_len > 0:
                body = self.rfile.read(content_len)

                """
                fname = None
                with tempfile.NamedTemporaryFile(prefix="artwork", dir=".", delete=False, suffix=".jpg") as f:
                    f.write(self.rfile.read(content_len))
                    fname = f.name
                self.logger.info(f"Artwork saved to {fname}")
                """
        elif content_type == HTTP_CT_DMAP:
            if content_len > 0:
                self.logger.info(parse_dxxp(self.rfile.read(content_len)))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.logger.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        # TODO: get actual playout latency
        self.send_header("Audio-Latency", "0")
        """
        if we are in a remote control session, we must send something here...
        """
        if GROUP_UUID:
            # Send device_info which now includes senderAddress (sender of groupUUID)
            res = writePlistToString({'type': 'updateInfo', 'value': device_info})
            self.send_header("Content-Length", len(res))
            self.send_header("Content-Type", HTTP_CT_BPLIST)
        self.end_headers()
        if GROUP_UUID:
            self.wfile.write(res)
    # End do_RECORD

    def do_SETRATEANCHORTIME(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            try:
                if content_len > 0:
                    body = self.rfile.read(content_len)

                    plist = readPlistFromString(body)
                    try:  # Sending thru a pipe, check for pipe related errors
                        if plist["rate"] == 1:
                            for s in self.server.streams:
                                if s.isAudio() and s.isInitialized():
                                    s.getAudioConnection().send(f"play-{plist['rtpTime']}")
                        if plist["rate"] == 0:
                            for s in self.server.streams:
                                if s.isAudio() and s.isInitialized():
                                    s.getAudioConnection().send("pause")
                    except OSError:
                        self.logger.error(f'SETRATEANCHORTIME error: {repr(e)}')
                    except AttributeError:
                        # Pipe not set up yet.
                        pass

                    self.logger.info(self.pp.pformat(plist))
            except IndexError:
                # Fixes some disconnects
                self.logger.error('Cannot process request; streams torn down already.')
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_TEARDOWN(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                if "streams" in plist:
                    for s in plist["streams"]:
                        stream_id = s["streamID"]
                        stream_type = s["type"]

                        if len(self.server.streams) > 0:
                            for st in self.server.streams:
                                if stream_type == st.getStreamType() and stream_id == st.getStreamID():
                                    st.teardown()
                        # Stream cull: build new list of non culled streams
                        self.server.streams[:] = [s for s in self.server.streams if not s.isCulled()]
                self.logger.info(self.pp.pformat(plist))
                if plist == {} and len(self.server.streams) == 0:
                    # Signal that session(?) is over: TODO: look at source
                    # HACK: Should look at which session the GUUID came from.
                    GROUP_UUID = None
                    self.server.event_proc.terminate()
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

        # Send flag that we're no longer active
        update_status_flags(StatusFlags.getRecvSessActive(StatusFlags))

    def do_SETPEERS(self):
        """
        A shorter format to set timing (PTP clock) peers.

        Content-Type: /peer-list-changed
        Contains [] array of IP{4|6}addrs:
        ['...::...',
         '...::...',
         '...']
        """
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            self.logger.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETPEERSX(self):
        # Extended format for setting timing (PTP clock) peers
        # Requires Ft52PeersExtMsg (bit 52)
        # Note: this method does not require defining in do_OPTIONS

        # Content-Type: /peer-list-changed-x
        # Contains [] array of:
        # {'Addresses': ['fe80::...',
        #         '...'],
        #   'ClockID': 000000000000000000,
        #   'ClockPorts': {GUID1: port,
        #                  GUID2: port,
        #                  GUIDN: port},
        #   'DeviceType': 0,
        #   'ID': GUID,
        #   'SupportsClockPortMatchingOverride': T/F}

        # SETPEERSX may require more logic when PTP is finished.
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            self.logger.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_FLUSH(self):
        self.logger.info(f'{self.command}: {self.path}')
        self.logger.debug(self.headers)

        if "RTP-Info" in self.headers:
            rtp_info = self.headers["RTP-Info"]
            seq, rtptime = rtp_info.split(';')
            seq = seq.split('=')[1]
            rtptime = rtptime.split('=')[1]
            try:
                for s in self.server.streams:
                    if s.isAudio() and s.isInitialized() and not s.isRCO():
                        s.getAudioConnection().send(f"flush_seq_rtptime-{seq}-{rtptime}")
            except OSError as e:
                self.logger.error(f'FLUSH error: {repr(e)}')
            except AttributeError as e:
                # Not ready yet
                pass

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

                mcp = MediaCommandParser(plist)
                self.logger.debug(mcp.getSupported())

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        # self.end_headers()
        remote_reply = b'\x00\x00\x00Jrply\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01aU\xc3\xe0\x00\x00\x00\x00bplist00\xd0\x08\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t'
        res = writePlistToString(remote_reply)
        # self.logger.debug(res)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_BPLIST)
        self.end_headers()
        self.wfile.write(res)


    def handle_feedback(self):
        self.handle_generic(feedback=True)

    def handle_audiomode(self):
        self.handle_generic()

    def handle_generic(self, feedback=False):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.logger.info(self.pp.pformat(plist))

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        if feedback:
            if len(self.server.streams) > 0:
                stream_data = {'streams': []}
                for s in self.server.streams:
                    stream_data['streams'].append(s.getDescriptor())
            else:
                stream_data = {}
            # self.logger.debug(stream_data)
            res = writePlistToString(stream_data)
            self.send_header("Content-Length", len(res))
            self.send_header("Content-Type", HTTP_CT_BPLIST)
        self.end_headers()
        if feedback:
            self.wfile.write(res)

    def handle_auth_setup(self):
        self.handle_X_setup('auth')

    def handle_fp_setup(self):
        self.handle_X_setup('fp')

    def handle_X_setup(self, op: str = ''):
        response = b''
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            # This is the session fairplay_keymsg (168 bytes long)
            self.fairplay_keymsg = body = self.rfile.read(content_len)

            if op == 'fp':
                pf = PlayFair()
                pf_info = PlayFair.fairplay_s()
                response = pf.fairplay_setup(pf_info, body)
            if op == 'auth':
                try:
                    plist = readPlistFromString(body)
                    self.logger.info(self.pp.pformat(plist))
                except InvalidPlistException as e:
                    # Use flags: 00088200405f4200 or -ftxor 51
                    self.logger.error('Unhandled edge-case encrypted setup')
                    self.send_response(404)
                    return

                if 'X-Apple-AT' in self.headers and self.headers["X-Apple-AT"] == '16':
                    """
                    Use flags: 144037111597568 / 0x830040DF0A00 or -ftxor 23 (RSA)
                    triggers: {'ascm': 1, 'tkrd': ['pair', 'auth', 'uuid']}
                    """

                    self.logger.error('Unhandled edge-case for unencrypted auth setup')
        if response:
            self.send_response(200)
            self.send_header("Content-Length", len(response))
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            if op == 'fp':
                self.wfile.write(response)
        else:
            self.logger.error('Unhandled edge-case: FairPlay 2 encryption not supported.')
            self.send_error(101)
            return

    def handle_pair_setup(self):
        self.handle_pair_SV('setup')

    def handle_pair_verify(self):
        self.handle_pair_SV('verify')

    def handle_pair_SV(self, op):
        body = self.rfile.read(int(self.headers["Content-Length"]))

        if not self.hap:
            self.hap = Hap(PI, DEBUG)
        if op == 'verify':
            res = self.hap.pair_verify(body)
        elif op == 'setup':
            res = self.hap.pair_setup(body)

        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", self.headers["Content-Type"])
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

        if self.hap.encrypted and self.hap.mfi_setup:
            self.logger.warning('MFi setup not yet possible. Disable feature bit 51.')
        elif self.hap.encrypted:
            hexdump(self.hap.accessory_shared_key) if DEBUG else ''
            self.ecdh_shared_key = self.hap.accessory_shared_key
            self.upgrade_to_encrypted(self.hap.accessory_shared_key)

    def handle_pair_add(self):
        self.handle_pair_ARL('add')

    def handle_pair_remove(self):
        self.handle_pair_ARL('remove')

    def handle_pair_list(self):
        self.handle_pair_ARL('list')

    def handle_pair_ARL(self, op):
        self.logger.info(f"pair-{op} {self.path}")
        self.logger.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            if op == 'add':
                res = self.hap.pair_add(body)
            elif op == 'remove':
                res = self.hap.pair_remove(body)
            elif op == 'list':
                res = self.hap.pair_list(body)
            hexdump(res) if DEBUG else ''
            self.send_response(200)
            self.send_header("Content-Type", self.headers["Content-Type"])
            self.send_header("Content-Length", len(res))
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            self.wfile.write(res)

    def handle_configure(self):
        global DEV_NAME
        global DEV_PROPS
        global STATUS_FLAGS
        global HK_ACL_LEVEL
        global HK_PW
        pwset = True
        cd_s = 'ConfigurationDictionary'
        acl_s = 'Access_Control_Level'
        acl = 0
        dn = DEV_NAME
        dn_s = 'Device_Name'
        hkac = True
        hkac_s = 'Enable_HK_Access_Control'
        pw = ''
        pw_s = 'Password'
        self.logger.info(f"configure {self.path}")
        self.logger.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            plist = readPlistFromString(body)
            self.logger.info(self.pp.pformat(plist))
            if acl_s in plist[cd_s]:
                # 0 == Everyone on the LAN
                # 1 == Home members
                # 2 == Admin members
                acl = int(plist[cd_s][acl_s])
                # Reassign any changes from HomeKit
                HK_ACL_LEVEL = acl
                DEV_PROPS.setDeviceACL(acl)
            if dn_s in plist[cd_s]:
                # reassign global device name that we get from HomeKit
                DEV_NAME = dn = plist[cd_s][dn_s]
                DEV_PROPS.setDeviceName(dn)
            if hkac_s in plist[cd_s]:
                hkac = bool(plist[cd_s][hkac_s])
                DEV_PROPS.setHKACL(hkac)
                if hkac:
                    update_status_flags(StatusFlags.getHKACFlag(StatusFlags), on=True)
                else:
                    update_status_flags(StatusFlags.getHKACFlag(StatusFlags))
            if pw_s in plist[cd_s]:
                """
                There seems to be a logic bug in iOS >= 14.8.1 whereby pw updates
                are slow or don't happen if you change pw settings too rapidly in
                homekit->allow speaker&tv access.
                """
                pw = plist[cd_s][pw_s]
                pwset = False if pw == '' else True
                if pwset:
                    update_status_flags(StatusFlags.getPWSetFlag(StatusFlags), on=True)
                else:
                    update_status_flags(StatusFlags.getPWSetFlag(StatusFlags))

                # reassign global password from HomeKit
                HK_PW = pw
                DEV_PROPS.setDevicePassword(pw)

        accessory_id, accessory_ltpk = self.hap.configure()
        configure_info = {
            'Identifier': accessory_id.decode('utf-8'),
            hkac_s: hkac,
            'PublicKey': accessory_ltpk,
            dn_s: dn,
            acl_s: acl or HK_ACL_LEVEL
        }
        if pw:
            configure_info['Password'] = pw or HK_PW

        res = writePlistToString(configure_info)
        self.logger.info(self.pp.pformat(configure_info))

        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_BPLIST)
        self.send_header("Server", self.version_string())

        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

    def handle_info(self):
        if "Content-Type" in self.headers:
            if self.headers["Content-Type"] == HTTP_CT_BPLIST:
                content_len = int(self.headers["Content-Length"])
                if content_len > 0:
                    body = self.rfile.read(content_len)

                    plist = readPlistFromString(body)
                    self.logger.info(self.pp.pformat(plist))
                    if "qualifier" in plist and "txtAirPlay" in plist["qualifier"]:
                        self.logger.info('Sending our device info')
                        self.logger.debug(self.pp.pformat(device_info))
                        res = writePlistToString(device_info)

                        self.send_response(200)
                        self.send_header("Content-Length", len(res))
                        self.send_header("Content-Type", HTTP_CT_BPLIST)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                        self.wfile.write(res)
                    else:
                        self.logger.error("No txtAirPlay")
                        self.send_error(404)
                        return
                else:
                    self.logger.error("No content")
                    self.send_error(404)
                    return
            else:
                self.logger.error(f"Content-Type: {self.headers['Content-Type']} | Not implemented")
                self.send_error(404)
        else:
            res = writePlistToString(device_info)
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
        self.logger.debug("----- ENCRYPTED CHANNEL -----")


def register_mdns(mac, receiver_name, addresses):
    global MDNS_OBJ

    info = ServiceInfo(
        "_airplay._tcp.local.",
        f"{receiver_name}._airplay._tcp.local.",
        addresses=addresses,
        port=7000,
        properties=mdns_props,
        server=f"{mac.replace(':', '')}@{receiver_name}._airplay.local.",
    )

    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)

    # Remove stale entries
    # This step causes problems in multiprocess: needs asyncio
    try:
        if MDNS_OBJ:
            zeroconf.update_service(info)
        else:
            # Push out new entries
            zeroconf.register_service(info)
            SCR_LOG.info("mDNS: service registered")
    except (NonUniqueNameException) as e:
        SCR_LOG.error(f'mDNS exception during registration: {repr(e)}')
    finally:
        pass
    return (zeroconf, info)


def unregister_mdns(zeroconf, info):
    try:
        asyncio.run(zeroconf.async_unregister_service(info))
        SCR_LOG.info("mDNS: Unregistering")
    except (NonUniqueNameException) as e:
        # Observed NonUniqueNameException once during testing
        SCR_LOG.error(f'mDNS exception during removal: {repr(e)}')
    finally:
        zeroconf.close()


class AP2Server(socketserver.ThreadingTCPServer):
    # Fixes 99% of scenarios on restart after we terminate uncleanly/crash
    # and port was not closed before crash (is still open).
    # AP2 client connects from random port.
    allow_reuse_address = True
    timeout = 60  # seconds

    def __init__(self, addr_port, handler):
        super().__init__(addr_port, handler)
        self.connections = {}
        """ Handle the HAP object here: it's not a fact that the HAP
        connection is torn down, when the sessions and streams are. This means
        HomeKit, RemoteControl and other niceties continue to work.
        """
        self.serv_addr, self.serv_port = addr_port
        # self.hap = None  # thread local, not global.
        self.event_proc = None
        self.event_port = None
        self.timing_proc = None
        self.timing_port = None
        self.enc_layer = False
        self.streams = []
        self.sessions = []
        log_string = f'{self.__class__.__name__}: {self.serv_addr}:{self.serv_port}'
        level = 'DEBUG' if DEBUG else 'INFO'
        self.logger = get_screen_logger(log_string, level=level)

    # Override
    def get_request(self):
        client_socket, client_addr = super().get_request()
        self.logger.info(f"Opened connection from {client_addr[0]}:{client_addr[1]}")
        self.connections[client_addr] = client_socket
        return (client_socket, client_addr)

    def upgrade_to_encrypted(self, client_address, shared_key):
        client_socket = self.connections[client_address]
        self.hap_socket = HAPSocket(client_socket, shared_key)
        self.logger.info(f"{current_thread().name}: Opened HAPSocket from {client_address[0]}:{client_address[1]}")
        self.connections[client_address] = self.hap_socket
        return self.hap_socket

    # Override
    def server_close(self):
        if self.logger:
            self.logger.debug('Removing AP2Server object.')
        self.hap = None
        self.hap_socket = None
        self.streams.clear()
        self.logger = None
        self.shutdown()


def list_network_interfaces():
    print("Available network interfaces:")
    for interface in ni.interfaces():
        print(f'  Interface: "{interface}"')
        addresses = ni.ifaddresses(interface)
        for address_family in addresses:
            if address_family in [ni.AF_INET, ni.AF_INET6]:
                for ak in addresses[address_family]:
                    for akx in ak:
                        if str(akx) == 'addr':
                            print(f"    {'IPv4' if address_family == ni.AF_INET else 'IPv6'}: {str(ak[akx])}")


def list_available_flags():
    print(f'[?] Available feature names:')
    for ft in FeatureFlags:
        print(f' {ft.name}')
    print('[?] Choose named features via their numbers. E.g. for Ft07, write: 7')


def generate_fake_mac():
    fakemac = int(random.getrandbits(48)).to_bytes(length=6, byteorder='big').hex()
    fm = ':'.join(map(str, [fakemac[i:i + 2] for i in range(0, len(fakemac), 2)]))
    return fm


if __name__ == "__main__":

    multiprocessing.set_start_method("spawn")
    parser = argparse.ArgumentParser(prog='AirPlay 2 receiver')
    mutexgroup = parser.add_mutually_exclusive_group()

    parser.add_argument("-fm", "--fakemac", help="Generate and use a random MAC for ethernet address.", action='store_true')
    parser.add_argument("-m", "--mdns", help="mDNS name to announce", default="myap2")
    parser.add_argument("-n", "--netiface", help="Network interface to bind to. Use the --list-interfaces option to list available interfaces.")
    parser.add_argument("-nv", "--no-volume-management", help="Disable volume management", action='store_true')
    parser.add_argument("-npm", "--no-ptp-master", help="Stops this receiver from being announced as the PTP Master",
                        action='store_true')
    mutexgroup.add_argument("-f", "--features", help="Features: a hex representation of Airplay features. Note: mutex with -ft(xxx)")
    mutexgroup.add_argument(
        "-ft", nargs='+', type=int, metavar='F',
        help="Explicitly enable individual Airplay feature bits. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftnot", nargs='+', type=int, metavar='F',
        help="Bitwise NOT toggle individual Airplay feature bits from the default. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftand", nargs='+', type=int, metavar='F',
        help="Bitwise AND toggle individual Airplay feature bits from the default. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftor", nargs='+', type=int, metavar='F',
        help="Bitwise OR toggle individual Airplay feature bits from the default. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftxor", nargs='+', type=int, metavar='F',
        help="Bitwise XOR toggle individual Airplay feature bits from the default. Use 0 for help.")
    parser.add_argument("--list-interfaces", help="Prints available network interfaces and exits.", action='store_true')
    parser.add_argument("--debug", help="Prints extra debug message e.g. HTTP headers.", action='store_true')

    args = parser.parse_args()

    DEBUG = args.debug
    if DEBUG:
        SCR_LOG = get_screen_logger('Receiver', level='DEBUG')
    else:
        SCR_LOG = get_screen_logger('Receiver', level='INFO')

    if args.list_interfaces:
        list_network_interfaces()
        exit(0)

    if args.netiface is None:
        print("[!] Missing --netiface argument. See below for a list of valid interfaces")
        list_network_interfaces()
        exit(-1)

    try:
        IFEN = args.netiface
        ifen = ni.ifaddresses(IFEN)
    except Exception:
        print("[!] Network interface not found.")
        list_network_interfaces()
        exit(-1)

    DISABLE_VM = args.no_volume_management
    DISABLE_PTP_MASTER = args.no_ptp_master
    DEV_PROPS = DeviceProperties(PI, DEBUG)
    DEV_NAME = args.mdns
    if(parser.get_default('mdns') != DEV_NAME):
        DEV_PROPS.setDeviceName(DEV_NAME)
    else:
        DEV_NAME = DEV_PROPS.getDeviceName()
    SCR_LOG.info(f"Name: {DEV_NAME}")
    pw = DEV_PROPS.getDevicePassword()
    hkacl = DEV_PROPS.isHKACLEnabled()
    if pw:
        STATUS_FLAGS ^= StatusFlags.getPWSetFlag(StatusFlags)
    if hkacl:
        STATUS_FLAGS ^= StatusFlags.getHKACFlag(StatusFlags)

    if args.features:
        # Old way. Leave for those who use this way.
        try:
            FEATURES = int(args.features, 16)
            SCR_LOG.info(f"Features:")
            SCR_LOG.info(FeatureFlags(FEATURES))
        except Exception:
            SCR_LOG.error("[!] Error with feature arg - hex format required")
            exit(-1)

    bitwise = args.ft or args.ftnot or args.ftor or args.ftxor or args.ftand
    # This param is mutex with args.features
    if bitwise:
        if (bitwise == [0]):
            list_available_flags()
            exit(0)
        else:
            try:
                flags = 0
                for ft in bitwise:
                    if ft > 64:
                        raise Exception
                    flags |= (1 << int(ft))
                if args.ft:
                    FEATURES = FeatureFlags(flags)
                elif args.ftnot:
                    FEATURES = FeatureFlags(~flags)
                elif args.ftand:
                    FEATURES &= FeatureFlags(flags)
                elif args.ftor:
                    FEATURES |= FeatureFlags(flags)
                elif args.ftxor:
                    FEATURES ^= FeatureFlags(flags)
                SCR_LOG.info(f'Chosen features: {flags:016x}')
                SCR_LOG.info(FeatureFlags(flags))
            except Exception:
                SCR_LOG.info("[!] Incorrect flags/mask.")
                SCR_LOG.info(f"[!] Proceeding with defaults.")
    SCR_LOG.info(f'Enabled features: {FEATURES:016x}')
    SCR_LOG.info(FEATURES)

    DEVICE_ID = None
    IPV4 = None
    IPV6 = None
    if ifen.get(ni.AF_LINK):
        if args.fakemac:
            DEVICE_ID = generate_fake_mac()
            while DEVICE_ID == ifen[ni.AF_LINK][0]["addr"]:
                DEVICE_ID = generate_fake_mac()
        else:
            DEVICE_ID = ifen[ni.AF_LINK][0]["addr"]
        DEVICE_ID_BIN = int((DEVICE_ID).replace(":", ""), base=16).to_bytes(6, 'big')
    if ifen.get(ni.AF_INET):
        IPV4 = ifen[ni.AF_INET][0]["addr"]
        IP4ADDR_BIN = socket.inet_pton(ni.AF_INET, IPV4)
    if ifen.get(ni.AF_INET6):
        IPV6 = ifen[ni.AF_INET6][0]["addr"].split("%")[0]
        IP6ADDR_BIN = socket.inet_pton(ni.AF_INET6, IPV6)

    setup_global_structs(args, isDebug=DEBUG)

    # Rudimentary check for whether v4/6 are still None (no IP found)
    if IPV4 is None and IPV6 is None:
        SCR_LOG.fatal("[!] No IP found on chosen interface.")
        list_network_interfaces()
        exit(-1)

    SCR_LOG.info(f"Interface: {IFEN}")
    SCR_LOG.info(f"Mac: {DEVICE_ID}")
    SCR_LOG.info(f"IPv4: {IPV4}")
    SCR_LOG.info(f"IPv6: {IPV6}")
    SCR_LOG.info("")

    MDNS_OBJ = register_mdns(DEVICE_ID, DEV_NAME, [IP4ADDR_BIN, IP6ADDR_BIN])

    SCR_LOG.info("Starting RTSP server, press Ctrl-C to exit...")
    try:
        PORT = 7000
        if IPV6 and not IPV4:
            with AP2Server((IPV6, PORT), AP2Handler) as httpd:
                IPADDR_BIN = IP6ADDR_BIN
                IPADDR = IPV6
                SCR_LOG.info(f"serving on {IPADDR}:{PORT}")
                httpd.serve_forever()
        else:  # i.e. (IPV4 and not IPV6) or (IPV6 and IPV4)
            with AP2Server((IPV4, PORT), AP2Handler) as httpd:
                IPADDR_BIN = IP4ADDR_BIN
                IPADDR = IPV4
                SCR_LOG.info(f"serving on {IPADDR}:{PORT}")
                httpd.serve_forever()

    except KeyboardInterrupt:
        pass
    except ConnectionResetError:
        # Weird client termination at the other end.
        pass
    finally:
        SCR_LOG.info("Shutting down mDNS...")
        unregister_mdns(*MDNS_OBJ)
