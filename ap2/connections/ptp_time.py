"""
# Simple, naïve PTP implementation in Python

# Basic listening and sync ability. Listens only to UDP unicast on ports 319+20.
# - systemcrash 2021
# Airplay only cares about *relative* sync, as does this implementation.
# No absolute or NTP references. It currently only slaves to other master clocks
# and follows the PTP election mechanism for grand masters, then syncs to those.
# This implementation also assumes (sub)Domain is 0.
# Apple Airplay uses unicast, not multi. It is specified in e.g.:
# Apple Vendor PTP Profile 2017
# Why the unicast model? Consumer grade network links where AP2 is in use
# are less stable (than e.g. carrier grade links), and will have continually
# fluctuating mean propagation delays, so the unicast model which continuously
# accounts for this, is utilized.
# The multicast model sends broadcasts. To measure individual mean link delays,
# it actively engages a unicast transmission with e.g. TLV 4-7 and reverts to
# multicast operation.
# License: GPLv2

Most behaviour in here is derived from PTP within AirPlay. Assume that Apple has its own
PTP Profile. So unless otherwise stated here, the values here apply to Apple's profile.

"""

import socket
import select
import threading
import multiprocessing
import enum
from enum import Flag
import random
import time
from collections import deque

"""
# UDP dest port: 319 for Sync, Delay_Req, Pdelay_Req, Pdelay_Resp;
# UDP dest port: 320 for other messages.
# Sources for this implementation:
# http://www.chronos.co.uk/files/pdfs/cal/TechnicalBrief-IEEE1588v2PTP.pdf
# http://ithitman.blogspot.com/2015/03/precision-time-protocol-ptp-demystified.html
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ptp.c
# https://github.com/ptpd/ptpd/tree/master/src
# https://www.nist.gov/system/files/documents/el/isd/ieee/tutorial-basic.pdf
# https://www.ieee802.org/1/files/public/docs2008/as-garner-1588v2-summary-0908.pdf
# in 2 step, we see Announce, Del_req, Del_resp, Followup, Sig, Sync
"""

"""
Apple PTP Limits
ppmLimit 10000
ppmNumerator 10000
ppmDenominator 1000000
filter shift 8

"""


class MsgType(enum.Enum):
    def __str__(self):
        # when we enumerate, only print the msg name w/o class:
        return self.name
    # 0x00-0x03 require accurate timestamps (event)
    SYNC                      = 0x00
    # receiver sends del_reqs message to figure out xceive delay
    DELAY_REQ                 = 0x01
    # path_del only for asymmetric routing topo
    PATH_DELAY_REQ            = 0x02
    PATH_DELAY_RESP           = 0x03
    # 0x08-0x0d do not require accurate timestamps (general)
    # time increment since last msg - offset
    FOLLOWUP                  = 0x08
    # sender gets del_resp to calculate RTT delay
    DELAY_RESP                = 0x09
    PATH_DELAY_RESP_FOLLOWUP  = 0x0A
    # Ann declares clock and type
    ANNOUNCE                  = 0x0B
    SIGNALLING                = 0x0C
    MANAGEMENT                = 0x0D


class ClkAccuracy(enum.Enum):
    def __str__(self):
        return self.name
    # GM = GrandMaster
    # 00-1F - reserved 1588:2008
    # 00-16 - reserved 1588:2019
    pS1                     = b'\x17'  # 1 picosec
    pS2_5                   = b'\x18'  # 2.5 picosec
    pS10                    = b'\x19'
    pS25                    = b'\x1a'
    pS100                   = b'\x1b'
    pS250                   = b'\x1c'
    nS1                     = b'\x1d'  # 1 nanosec
    nS2_5                   = b'\x1e'
    nS10                    = b'\x1f'
    nS25                    = b'\x20'  # 25 nanosec
    nS100                   = b'\x21'
    nS250                   = b'\x22'
    µS1                     = b'\x23'  # 1 microsec
    µS2_5                   = b'\x24'
    µS10                    = b'\x25'
    µS25                    = b'\x26'
    µS100                   = b'\x27'
    µS250                   = b'\x28'
    mS1                     = b'\x29'  # 1 millisec
    mS2_5                   = b'\x2a'
    mS10                    = b'\x2b'
    mS25                    = b'\x2c'
    mS100                   = b'\x2d'
    mS250                   = b'\x2e'
    S1                      = b'\x2f'  # 1 sec
    S10                     = b'\x30'
    GTS10                   = b'\x31'  # >10sec
    # 32-7F reserved
    # 80-FD profiles
    UNKNOWN                 = b'\xfe'
    RESERVED                = b'\xff'


class ClkSource(enum.Enum):
    def __str__(self):
        return self.name
    ATOMIC                  = b'\x10'
    GPS_GNSS                = b'\x20'
    TERRESTRIAL_RADIO       = b'\x30'
    SERIAL_TIME_CODE        = b'\x39'
    PTP_EXTERNAL            = b'\x40'
    NTP_EXTERNAL            = b'\x50'
    HAND_SET                = b'\x60'
    OTHER                   = b'\x90'
    INTERNAL_OSCILLATOR     = b'\xa0'
    # F0-FE - PROFILES
    # FF - Reserved


class ClkClass(enum.Enum):
    def __str__(self):
        return self.name
    # RESERVED 000-005
    PRIMARY_REF_LOCKED      = b'\x06'  # 6
    PRIMARY_REF_UNLOCKED    = b'\x07'  # 7
    # RESERVED 008-012
    LOCKED_TO_APP_SPECIFIC  = b'\x0d'  # 13
    UNLOCKD_FR_APP_SPECIFIC = b'\x0e'  # 14
    # RESERVED 015-051
    PRC_UNLOCKED_DESYNC     = b'\x34'  # 52
    # RESERVED 053-057
    APP_UNLOCKED_DESYNC     = b'\x3a'  # 58
    # RESERVED 059-067
    # AltProfiles 068-122
    # RESERVED 123-132
    # AltProfiles 133-170
    # RESERVED 171-186
    PRC_UNLOCKED_DESYNC_ALT = b'\xbb'  # 187
    # RESERVED 188-192
    APP_UNLOCKED_DESYNC_ALT = b'\xc1'  # 193
    # RESERVED 194-215
    # Profiles 216-232
    # RESERVED 233-247
    DEFAULT                 = b'\xf8'  # 248
    # RESERVED 249-254
    SLAVE_ONLY              = b'\xff'  # 255


class TLVType(enum.Enum):
    # Use b'\x??\x??' so we can direct binary compare
    def __str__(self):
        return self.name
    RESERVED                    = b'\x00\x00'
    # standard:
    MANAGEMENT                  = b'\x00\x01'
    MANAGEMENT_ERROR_STATUS     = b'\x00\x02'
    ORGANIZATION_EXTENSION      = b'\x00\x03'
    # optional:
    REQUEST_UNICAST_XMISSION    = b'\x00\x04'
    GRANT_UNICAST_XMISSION      = b'\x00\x05'
    CANCEL_UNICAST_XMISSION     = b'\x00\x06'
    ACK_CANCEL_UNICAST_XMISSION = b'\x00\x07'
    # optional trace
    PATH_TRACE                  = b'\x00\x08'
    # optional timescale
    ALT_TIME_OFFSET_INDICATOR   = b'\x00\x09'
    # RESERVED for std TLV  000A-1FFF
    # From 2008 std - unused in 2019 std:
    # AUTHENTICATION              = b'\x20\x00'
    # AUTHENTICATION_CHALLENGE    = b'\x20\x01'
    # SECURITY_ASSOCIATION_UPDATE = b'\x20\x02'
    # CUM_FREQ_SCALE_FACTOR_OFFSE = b'\x20\x03'
    # v2.1:
    # Experimental 2004-202F
    # RESERVED   2030-3FFF
    # IEEE 1588 reserved 4002-7EFF
    # Experimental 7F00-7FFF
    # Interesting 8000-8009
    PAD                         = b'\x80\x08'
    AUTHENTICATIONv2            = b'\x80\x09'
    # IEEE 1588  RESERVED   800A-FFEF
    # RESERVED   FFEF-FFFF


def bigint(data, signed=False):
    return int.from_bytes(data, byteorder='big', signed=signed)


class PTPMsg:
    class MsgFlags(Flag):
        def __str__(self):
            return self.name
        alternateMaster = 1  # 1<<0 Announce, Sync, Follow_Up, Delay_Resp
        twoStep = 2          # 1<<1 Sync, Pdelay_Resp
        unicast = 4          # 1<<2 ALL
        profile1 = 32        # 1<<5 ALL
        profile2 = 64        # 1<<6 ALL
        reserved = 128       # 1<<7

    # (2019:) Announce only:
    class MsgFlagsB(Flag):
        def __str__(self):
            return self.name
        leap61 = 1                 # 1<<0
        leap59 = 2                 # 1<<1
        currentUtcOffsetValid = 4  # 1<<2
        ptpTimescale = 8           # 1<<3 ALL (802.1AS)
        timeTraceable = 16         # 1<<4
        frequencyTraceable = 32    # 1<<5
        # Profile specific:
        synchronizationUncertain = 64  # 1<<6

    @staticmethod
    def getTLVs(msgLen, data, start):
        # TLV = Type, Length, Value Identifier
        tlvSeq = []
        while(msgLen - start) > 0:
            tlvType = TLVType(data[start: start + 2])
            tlvLen = bigint(data[start + 2: start + 4])
            # 3 byte OID + 3 byte subOID
            # V in TLV are even in length.

            """
            1588-2019: 14.3.2 TLV member specifications
            All organization-specific TLV extensions shall have
            the format specified in Table 53:
            bitfield       | Octets | TLV offset
            tlvType             | 2 | 0
            lengthField         | 2 | 2
            organizationId      | 3 | 4
            organizationSubType | 3 | 7
            dataField           | N | 10
            """
            if tlvType == TLVType.ORGANIZATION_EXTENSION:
                # Usually 00:80:c2:00:00:01 within FOLLOWUP
                # https://hwaddress.com/mac-address-range/00-0D-93-00-00-00/00-0D-93-FF-FF-FF/
                # Apple: 00:0d:93 sub: 00:00:0x => meaning: defined by Apple.
                #   contains clockID(mac)+port
                tlvOID = data[start + 4: start + 10]
                # Exclude the OID from data, tlvLen includes OID
                tlvData = data[start + 10:start + 4 + tlvLen]

                tlvSeq.append([tlvType, tlvLen, tlvOID, tlvData])

            elif tlvType == TLVType.PATH_TRACE:
                """
                1588-2019: 16.2.5 PATH_TRACE TLV specification
                The PATH_TRACE TLV format shall be as specified in Table 115.
                bitfield       | Octets | TLV offset
                tlvType             | 2 | 0
                lengthField         | 2 | 2
                pathSequence        | 8N| 4

                N is equal to stepsRemoved+1 (see 10.5.3.2.6). The size of the pathSequence array
                increases by 1 for each time-aware system that the Announce information traverses.
                """
                tlvUnitSize = 8  # bytes
                tlvRecordAmt = int(tlvLen / tlvUnitSize)
                # https://blog.meinbergglobal.com/2019/12/06/tlvs-in-ptp-messages/
                tlvPathSequence = [None] * tlvRecordAmt
                for x in range(0, tlvRecordAmt):
                    tlvPathSequence[x] = (data[
                        start + 4 + (x * tlvUnitSize):
                        start + 4 + tlvUnitSize + (x * tlvUnitSize)
                    ])
                return tlvPathSequence

            # still in the while loop
            start += tlvLen + 4  # 4 byte TLV header
        return tlvSeq if len(tlvSeq) > 0 else None

    def __init__(self, data, msg_type):
        self.hasTLVs = False
        # 2019: majorSdoId, 802.1AS: transportSpecific
        # self.majorSdoId = (data[0] & 0b11110000)
        # self.v1_compat = (data[0] & 0b00010000) >> 4
        # self.msg_type = MsgType(data[0] & 0b00001111)
        self.msg_type = msg_type
        # self.ptp_version= data[1] & 0b00001111 #) >> 0
        self.msgLength = bigint(data[2: 4])
        if len(data) == self.msgLength:
            # domain: 0 = default | 1 = alt 1 | 3 = alt 3 | 4-127, user defined.
            # (sub)domainNumber in AP2 implementation: Assume 0.
            # self.domainNumber = data[4]
            # 2019: data[5] is minorSdoId, 2008/802.1AS: reserved
            # data[5] is 1 Reserved byte
            # self.minorSdoId = data[5]
            self.msgFlags = PTPMsg.MsgFlags(data[6])
            # self.msgFlagsB = PTPMsg.MsgFlagsB(data[7])
            """
            Semantics dictate that correction is always ZERO for
            -Announce
            -Signaling
            -PTP mgmt
            """
            self.correctionNanoseconds = bigint(data[8: 14])
            # unlikely we will ever deal with subNanoSec or ever be accurate in Python
            # self.correctionSubNanoseconds = bigint(data[14: 16])
            # data[16:20][0] is 4 Reserved bytes
            # Retain *Identity as bytes (no performance hit):
            self.clockIdentity = data[20: 28]
            # SrcPortNumber = ID for the sender, whose IP may have multiple ports.
            self.sourcePortNumber = bigint(data[28: 30])
            self.sequenceID = bigint(data[30: 32])
            # unnecessary - from ptpv1:
            # self.control = data[32]
            """
            logMessagePeriod / Interval: for Sync, Followup, Del_resp
            multicast = log2(interval between multicast messages)
            y = log2(x) => if lMP = -2, x = 0.25 sec i.e. send 4 Sync every second.
            -3 => 8 per second.
            Sync: -7 -> 1 (i.e. from 128/sec to 1 per 2 sec)
            Ann : -3 -> 3 (i.e. from 8/sec   to 1 per 8 sec)
            Delay_Resp: def -4 (16/sec) | -7 -> 6 (i.e. from 128/sec to 1 per 64 sec)
            """
            self.logMessagePeriod = bigint(data[33:34], signed=True)
            # Relevant to all but Sig:
            if not self.msg_type == MsgType.SIGNALLING:
                self.originTimestampSec = bigint(data[34: 40])
                self.originTimestampNanoSec = bigint(data[40: 44])


class PTPSyncMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)


class PTPAnnounceMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        """
        NTP Seconds -> PTP Seconds: NTP Seconds ─ 2 208 988 800 + currentUtcOffset
        PTP Seconds -> NTP Seconds: PTP Seconds + 2 208 988 800 ─ currentUtcOffset
        GPS Seconds = (GPS Weeks × 7 × 86 400) + GPSSecondsInLastWeek
        (GPS week number needs to include 1024 × number of rollovers)
        GPS Seconds -> PTP Seconds: GPS Seconds + 315 964 819
        PTP Seconds -> GPS Seconds: PTP Seconds ─ 315 964 819
        Until we convert timescales, UTCOffset is unused.
        # self.originCurrentUTCOffset = bigint(data[44: 46])
        """
        # skip 1 reserved byte
        # GM determined by (lower = better):
        # prio1 < Class < Accuracy < Variance < prio2 < Ident(mac)
        # Dump the whole range 47-61. It can be directly compared as binary.
        self.systemIdentity = data[47:61]

        self.prio01 = data[47]
        # ClockClass = Quality Level (QL)
        self.gmClockClass = data[48:49]
        self.gmClockAccuracy = data[49:50]
        # variance: lower = better. Based on Allan Variance / Sync intv
        # PTP variance is equal to Allan variance multiplied by (τ^2)/3,
        # where τ is the sampling interval
        # Don't coerce gmClockVariance to an int in this AP2 implementation.
        # Small CPU gain. Leave for when we do more than master compares.
        self.gmClockVariance = data[50: 52]
        self.prio02 = data[52]
        self.gmClockIdentity = data[53: 61]

        self.localStepsRemoved = bigint(data[61: 63])
        self.timeSource = ClkSource(data[63:64])
        tlvStart = 64
        self.hasTLVs = (self.msgLength - tlvStart) > 0
        if self.hasTLVs:
            self.tlvPathSequence = self.getTLVs(self.msgLength, data, tlvStart)


class PTPDelay_RqMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)


class PTPDelay_RspMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        self.rcvTimestampSec = self.originTimestampSec
        self.rcvTimestampNanoSec = self.originTimestampNanoSec
        self.requestingSrcPortIdentity = data[44: 52]  # mac+port
        self.requestingSrcPortNumber = bigint(data[52: 54])  # ID


class PTPFollow_UpMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        self.preciseOriginTimestampSec = self.originTimestampSec
        self.preciseOriginTimestampNanoSec = self.originTimestampNanoSec
        # in Airplay2, followups have TLVs
        tlvStart = 44
        self.hasTLVs = (self.msgLength - tlvStart) > 0
        if self.hasTLVs:
            self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)


class PTPSigMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        # self.targetPortIdentity = data[34: 42]
        # self.targetPortNumber = bigint(data[42: 44])
        tlvStart = 44
        self.hasTLVs = (self.msgLength - tlvStart) > 0
        if self.hasTLVs:
            self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)


"""
# Currently unused in Airplay:
class PTPPath_Delay_RqMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        # self.reserved = bigint(data[44: 54])


# Currently unused in Airplay:
class PTPPath_Delay_RspMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        self.requestReceiptTimestampSec = self.originTimestampSec
        self.requestReceiptTimestampNanoSec = self.originTimestampNanoSec
        self.requestingPortIdentity = data[44: 54]


# Currently unused in Airplay:
class PTPPath_Delay_Rsp_Follow_UpMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        self.responseOriginTimestampSec = self.originTimestampSec
        self.responseOriginTimestampNanoSec = self.originTimestampNanoSec
        self.requestingPortIdentity = data[44: 54]


# Currently unused in Airplay:
class PTPManagementMsg(PTPMsg):
    def __init__(self, data, msg_type):
        super().__init__(data, msg_type)
        self.targetPortIdentity = data[34: 44]
        self.startingBoundaryHops = data[44]
        self.boundaryHops = data[45]
        self.actionField = data[46] & 0b00011111
        # self.reserved  = data[47]
        tlvStart = 48
        self.hasTLVs = (self.msgLength - tlvStart) > 0
        if self.hasTLVs:
            self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)
"""


class PTPForeignMaster:
    def __init__(self):
        self.sourcePortNumber = {}
        self.announceAmount = 0

    def __init__(self, data, arrival):
        self.sourcePortNumber = {data.gmClockIdentity, data.sourcePortNumber}
        self.announceAmount = 0
        # 9.3.2.4.3 : array of fm announces within FOREIGN_MASTER_TIME_WINDOW
        self.announceMessages = deque([data] * 4, maxlen=4)
        # Statistical code-golf
        self.announceMessageArrival_ts = deque([arrival] * 10, maxlen=10)
        self.announceMessageArrivalDeltas = deque([0] * 10, maxlen=10)

    def inc(self):
        self.announceAmount += 1

    def setMostRecentAMsg(self, data, arrival):
        self.inc()
        self.announceMessages.append(data)
        self.announceMessageArrival_ts.append(arrival)
        self.announceMessageArrivalDeltas.append(arrival - self.announceMessageArrival_ts[len(self.announceMessageArrival_ts) - 2])
        # self.checkMasterQuality()

    def checkMasterQuality(self):
        # TODO: Verify the quality of the Master's announce timing.
        # This is not mandated in the standard, it's just code golf when it's on the receiver :)
        # 1588:2019: 7.6.3.1 and 7.6.4.1:
        # parentDS.observedParentOffsetScaledLogVariance
        # parentDS.observedParentClockPhaseChangeRate: fractional freq offset * 2^40
        # 1588:2019: 9.5.8
        """
        ...the value of the arithmetic mean of the intervals, in seconds,
        between message transmissions is within ±30% of the value of 2 ** portDS.logAnnounceInterval

        Also, a PTP Port shall transmit Announce messages such that:
         at least 90% of the inter-message intervals are within ±30% of
         2 ** portDS.logAnnounceInterval.
         The interval between successive Announce messages should not exceed
         twice the value of 2** portDS.logAnnounceInterval,
         to prevent causing an announceReceiptTimeout event.
        """
        QLength = 10 - self.announceMessageArrivalDeltas.count(0)
        ArithMean = sum(self.announceMessageArrivalDeltas) / QLength
        AInterval = (2 ** self.getMostRecentAMsg().logMessagePeriod) * 10**9
        isWithin = ((AInterval * 0.7) < ArithMean and ArithMean < (AInterval * 1.3))
        # i.e. within ±30%

    def getAnnounceAmt(self):
        return self.announceAmount

    def getMostRecentArrivalNanos(self):
        return self.announceMessageArrival_ts[len(self.announceMessageArrival_ts) - 1]

    def getMostRecentAMsg(self):
        return self.announceMessages[len(self.announceMessages) - 1]

    def __lt__(self, other):
        return (self.getMostRecentAMsg().systemIdentity
                < other.getMostRecentAMsg().systemIdentity)

    def __gt__(self, other):
        return (self.getMostRecentAMsg().systemIdentity
                > other.getMostRecentAMsg().systemIdentity)

    def __eq__(self, other):
        return (self.getMostRecentAMsg().systemIdentity
                == other.getMostRecentAMsg().systemIdentity)


class PTPPortState(enum.Enum):
    def __str__(self):
        # so when we enumerate, we only print the msg name w/o class:
        return self.name
    INITIALIZING = 0x1
    FAULTY = 0x2
    DISABLED = 0x3
    LISTENING = 0x4
    # no code yet to run as MASTER
    PRE_MASTER = 0x5
    MASTER = 0x6
    PASSIVE = 0x7
    UNCALIBRATED = 0x8
    SLAVE = 0x9



class PTP():
    class CFG(Flag):
        # Config(16383) / Config(0x3FFF) toggles everything on.
        ShowNothing             = 0
        ShowTLVs                = 1     # 1<<0
        ShowSYNC                = 2     # 1<<1
        ShowDELAY_REQ           = 4     # 1<<2
        ShowPATH_DELAY_REQ      = 8     # 1<<3
        ShowPATH_DELAY_RESP     = 16    # 1<<4
        ShowFOLLOWUP            = 32    # 1<<5
        ShowDELAY_RESP          = 64    # 1<<6
        ShowPATH_DELAY_FOLLOWUP = 128   # 1<<7
        ShowANNOUNCE            = 256   # 1<<8
        ShowSIGNALLING          = 512   # 1<<9
        ShowMANAGEMENT          = 1024  # 1<<10
        ShowMasterPromotion     = 2048  # 1<<11
        ShowPortStateChanges    = 4096  # 1<<12
        ShowMeanPathDelay       = 8192  # 1<<13
        ShowDebug               = 16384  # 1<<14
        SetApplePTPProfile      = 32768  # 1<<15

    def __init__(self, if_mac, IFEN=None, IPV4=None, IPV6=None, p_flags=0):
        self._IFEN = IFEN
        self._IPV4 = IPV4
        self._IPV6 = IPV6
        self.cfg = self.CFG(p_flags)
        if self.cfg & self.CFG.ShowDebug:
            print(self.cfg)
        # Test individual flags with e.g.:
        # self.cfg |= self.CFG.ShowMeanPathDelay
        self.RECV_BUFFER = 180     # Big enough to hold chunky IPv6 Followup
        self.portEvent319 = 319    # Sync msgs / Event Port
        self.portGeneral320 = 320  # Followup msgs / General port
        self.gmClockIdentity = None
        self.gmSystemIdentity = b''
        self.t1_arr_nanos = 0
        self.t1_ts_s = 0
        self.t1_ts_ns = 0
        self.t1_corr = 0
        self.t2_arr_nanos = 0
        self.t2_ts_s = 0
        self.t2_ts_ns = 0
        self.t3_egress_nanos = 0
        self.t4_arr_at_gm_nanos = 0
        self.ms_propagation_delay = 0
        # Limit Queues to 20 entries
        self.QLength = 20
        self.adjustedMaster_ts = 0
        self.meanDelay = 0
        self.syncCorrection_ts = 0
        self.offsetFromMaster_ti = 0
        self.offsetFromMaster_tiMean = 0
        # deque = O(1) perf
        self.offsetFromMaster_tiValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.meanPathDelay_ti = 0  # bi-directional
        self.meanPathDelay_tiMean = 0  # mean of several bi-di results
        self.meanPathDelay_tiValues = deque([0] * self.QLength, maxlen=self.QLength)
        # stuff from TLVs
        self.firstDelta = True
        self.cumulativeScaledRateOffset = 0
        self.scaledLastGmPhaseChangeM = 0
        self.scaledLastGmPhaseChangeL = 0
        self.scaledLastGmFreqChange = 0
        self.gmTimeBaseIndicator = 0
        self.gmTimeBaseIndicatorOld = 0
        # neighborRateRatio is the upstream_clock_mhz:this_clock_mhz e.g. 10.002 / 9.998 = 1.004
        self.neighborRateRatio = 1    # [freq Local (PTP) Clock of upstream PTP]:[freq Local (PTP) Clock of this PTP]
        # cumulativeRateRatio: cumulative effect of on-the-path-hither from GM neighborRateRatios e.g. 1.004 * 1.003 = 1.0034
        self.cumulativeRateRatio = 1  # [freq GM Clock]:[freq Local (PTP) Clock of this PTP]
        self.processingOverhead = 0
        self.syncSequenceID = 0
        self.DelayReq_PortNumber = 32768
        self.DelayReq_template = bytearray.fromhex(
            '1102002c00000408000000000000000000000000'
            '01020304050600018000000100fd00000000000000000000')
        if(if_mac is not None):
            # DelayReq_template contains dummy MAC '010203040506'
            # add 2 empty bytes for 'PTP Port' to end of mac:
            self.if_mac = if_mac << 16
            self.if_mac_bytes = (if_mac << 16).to_bytes(8, byteorder='big')
            self.DelayReq_template[20:28] = self.if_mac_bytes
        else:
            self.if_mac = int('010203040506')
        self.DelayReq_template[28:30] = self.DelayReq_PortNumber.to_bytes(2, byteorder='big')
        self.portStateChange(PTPPortState.INITIALIZING)
        self.PTPcorrection = 0
        self.fML = []  # <foreignMasterList> # 9.3.2.4.6 Size of <foreignMasterList> min 5
        """
        Each entry of the <foreignMasterList> contains two or three members:
        - <foreignMasterList>[].foreignMasterPortIdentity,
        - <foreignMasterList>[].foreignMasterAnnounceMessages, and optionally
        - <foreignMasterList>[].mostRecentAnnounceMessage.
        """
        self.fMTW = 4  # FOREIGN_MASTER_TIME_WINDOW = 4 announceInterval
        self.fMThr = 2  # FOREIGN_MASTER_THRESHOLD 2 Announce msg within FOREIGN_MASTER_TIME_WINDOW
        """
        announceReceiptTimeoutInterval = portDS.announceReceiptTimeout * announceInterval
        """
        # 7.7.3.1 portDS.announceReceiptTimeout:
        # "Although 2 is permissible, normally the value should be at least 3."
        self.announceReceiptTimeout = 3

        """
        L.4.7 L1SyncReceiptTimeout
        This value = # of elapsed L1SyncIntervals that must pass without reception of the
        L1_SYNC TLV before the L1_SYNC TLV reception timeout occurs (see L.6.3).
        The default init val and allowed values spec'd in the applicable PTP Profile.
        """
        self.syncReceiptTimeout = 3
        # 13.3.2.14 logMessageInterval = 0x7F in unicast.
        # I.3.2 PTP attribute values
        # ... The default value of initialLogSyncInterval (see 10.6.2.3) is –3.
        self.initialLogSyncInterval = -3
        # ... The default value of initialLogAnnounceInterval is 0.
        self.initialLogAnnounceInterval = 0
        # ... The default value of initialLogPdelayReqInterval is 0.
        self.initialLogPdelayReqInterval = 0

        if(self.cfg & self.CFG.SetApplePTPProfile):
            """ https://github.com/rroussel/OpenAvnu/blob/ArtAndLogic-aPTP-changes/daemons/gptp/gptp_cfg.ini
            # Per the Apple Vendor PTP profile
            initialLogAnnounceInterval = 0
            initialLogSyncInterval = -3
            # Seconds:
            announceReceiptTimeout = 120

            # Per the Apple Vendor PTP profile (8*announceReceiptTimeout)
            syncReceiptTimeout = 960
            """
            # prio1 & prio2 = 248 and accuracy = 254
            self.initialLogAnnounceInterval = 0
            self.announceReceiptTimeout = 120
            self.initialLogSyncInterval = -3
            self.syncReceiptTimeout = 8 * self.announceReceiptTimeout

        self.announceInterval = 2**self.initialLogAnnounceInterval
        self.syncInterval = 2**self.initialLogSyncInterval
        # Unused in airplay: no PathDelay msgs.
        self.pdelayReqInterval = 2**self.initialLogPdelayReqInterval

        # count down nanos from last Announce - expires current GM
        self.lastAnnounceFromMasterNanos = 0
        # count down nanos from last Sync - expires current GM
        self.lastSyncFromMasterNanos = 0

        self.network_time_ns = 0
        self.network_time_monotonic_ts = time.monotonic_ns()

    def promoteMaster(self, ptpmsg, reason):
        self.gmClockIdentity = ptpmsg.gmClockIdentity
        self.gmSystemIdentity = ptpmsg.systemIdentity
        if(self.cfg & self.CFG.ShowMasterPromotion):
            print("New GM Clock promoted: "
                  f"{ptpmsg.gmClockIdentity.hex()} (Prio{ptpmsg.prio01}/{ptpmsg.prio02})",
                  f"reason: {reason}"
                  )
        # reset cumulative mean values to 0
        self.offsetFromMaster_tiValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.meanPathDelay_tiValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.portStateChange(PTPPortState.SLAVE)
        self.announceInterval = 2 ** ptpmsg.logMessagePeriod

    def compareMaster(self, ptpmsg):
        # This algo promotes a new master if its properties are better than currently elected GM
        # prio1 < Class < Accuracy < Variance < prio2 < Ident(mac)
        # Lower values == "better"
        if self.gmClockIdentity is None:
            self.promoteMaster(ptpmsg, "reset")
        else:
            if (ptpmsg.systemIdentity < self.gmSystemIdentity):
                self.promoteMaster(ptpmsg, "better GM")
                self.fML = []
            # else:
                # retain current GM

    def sendDelayRequest(self, sequenceID):
        self.DelayReq_template[30:32] = sequenceID.to_bytes(2, byteorder='big')
        return self.DelayReq_template

    def portStateChange(self, PTPPortState):
        self.portState = PTPPortState
        if (self.cfg & self.CFG.ShowPortStateChanges):
            print(f"PTP State: {self.portState}")
        self.syntonize()

    def getPortState(self):
        return self.portState

    def isKnownForeignMaster(self, ptpfm, ptpmsg, arrivalNanos):
        """
        Looks at our list of foreignMaster candidates and when we have enough
        Announce msgs from one, we kick off the BMCA: compareMaster()
        """
        """
        9.3.2.5 Qualification of Announce messages

        c) Unless otherwise specified by the option of 17.7, if the sender of S
        is a foreign master F, and fewer than FOREIGN_MASTER_THRESHOLD distinct
        Announce messages from F have been received within the most recent
        FOREIGN_MASTER_TIME_WINDOW interval, S shall not be qualified. Distinct
        Announce messages are those that have different sequenceIds, subject to
        the constraints of the rollover of the UInteger16 data type used for
        the sequenceId field.
        ...
        d) If the stepsRemoved field of S is 255 or greater, S shall not be
        qualified.
        ...
        e) This specification “e” is optional. ...
        ...
        f) Otherwise, S shall be qualified.
        """
        if ptpmsg.localStepsRemoved >= 255:
            return False

        if ptpfm not in self.fML:
            self.fML.append(ptpfm)
            # first entry means count == 0, so we skip sorting/comparing
            return False
        else:
            self.fML[self.fML.index(ptpfm)].setMostRecentAMsg(ptpmsg, arrivalNanos)
            # check previous Announce arrivalNanos
            lMP = 2 ** ptpmsg.logMessagePeriod  # e.g. 2^-2 = 0.25 sec
            # check interarrival diff of current and stored Announce nanos is
            # less than FOREIGN_MASTER_TIME_WINDOW * logMessagePeriod
            considerBMCA = ((arrivalNanos - self.fML[
                self.fML.index(ptpfm)]
                .getMostRecentArrivalNanos()) * 10**-9) < (self.fMTW * lMP)  # e.g. 4 * 0.25 = 1 sec
            self.fML.sort()  # keep fML list sorted, and mash [0] into BMCA when time comes
            if (self.fML[self.fML.index(ptpfm)].getAnnounceAmt() >= self.fMThr
               and considerBMCA):
                # run BMCA
                self.compareMaster(self.fML[0].getMostRecentAMsg())
            return True

    def calcRateDelta(self, m_ts, s_ts):
        if(self.firstDelta):
            self.prior_sync_ts = s_ts
            self.prior_master_ts = m_ts
            self.firstDelta = False
            return 1
        sync_delta = s_ts - self.prior_sync_ts
        master_delta = m_ts - self.prior_master_ts

        if sync_delta != 0:
            offset = master_delta / sync_delta
        else:
            offset = 1

        if m_ts < self.prior_master_ts:
            # some packet order problem
            return 1

        self.prior_sync_ts = s_ts
        self.prior_master_ts  = m_ts
        return offset

    def handlemsg(self, ptpmsg, address, timestampArrival, processingOverhead):
        # print(f"entered handlemsg() with {ptpmsg.sequenceID} and {self.syncSequenceID}")
        thinning = 100  # print msg every x msgs
        # port 319
        if (isinstance(ptpmsg, PTPSyncMsg)
           or isinstance(ptpmsg, PTPDelay_RqMsg)):

            if(((self.cfg & self.CFG.ShowSYNC) or (self.cfg & self.CFG.ShowDELAY_REQ))
               and (ptpmsg.sequenceID % thinning == 0)):
                print(f"PTP319 {ptpmsg.msg_type: <12}",
                      f"srcprt-#: {ptpmsg.sourcePortNumber:05d}",
                      f"clockId: {ptpmsg.clockIdentity.hex()}",
                      f"seq-ID: {ptpmsg.sequenceID:08d}",
                      f"Time: {ptpmsg.originTimestampSec}.{ptpmsg.originTimestampNanoSec:09d}",
                      )
                # print(f"processingOverhead for {ptpmsg.msg_type}:{processingOverhead:.9f}")

            # were we master, here is when we would respond to DELAY_REQ with DELAY_RESP
            # upon receipt of each Sync, we should respond with DELAY_REQ with same seqID
            if (isinstance(ptpmsg, PTPSyncMsg)
               and self.gmClockIdentity is not None
               and ptpmsg.clockIdentity == self.gmClockIdentity):
                self.lastSyncFromMasterNanos = timestampArrival
                if ptpmsg.msgFlags.twoStep:
                    # Seems to always be 0 in AP2:
                    self.syncCorrection_ts = ptpmsg.correctionNanoseconds
                    # Calculate ms_propagation_delay in FOLLOWUP
                    self.t2_arr_nanos = timestampArrival  # <-- syncEventIngressTimestamp
                    self.t2_ts_s = ptpmsg.originTimestampSec
                    self.t2_ts_ns = ptpmsg.originTimestampNanoSec
                    self.syncSequenceID = ptpmsg.sequenceID
                    # assign t3 to delay_req egress timestamp
                    self.t3_egress_nanos = time.monotonic_ns()
                    return self.sendDelayRequest(self.syncSequenceID)
                # else: #PTP in airplay does not use 1-step
                #     #iPhone PTP sends ptpmsg.originTimestamp(Nano)Sec = 0... so this won't work
                #     #1-step: must calculate t2-t1 diff here.
                #     self.t1_arr_nanos = ptpmsg.originTimestampSec + (ptpmsg.originTimestampNanoSec / 10 ** 9)
                #     self.ms_propagation_delay = t2_arr - t1_arr

        elif(isinstance(ptpmsg, PTPDelay_RspMsg)
             and ptpmsg.requestingSrcPortIdentity == self.if_mac):
            """
            IEEE1588-2019 Spec says:
            <meanPathDelay> = [(t2 – t1) + (t4 – t3)]/2 = [(t2 – t3) + (t4 – t1)]/2

            # 11.3.2 / e2) If the received Sync message indicated that a
              Follow_Up message will be received, the <meanPathDelay> shall be
              computed as:

            <meanPathDelay> = [(t2 - t3) + (receiveTimestamp of Delay_Resp
            message – preciseOriginTimestamp of Follow_Up message) –
            <correctedSyncCorrectionField> - correctionField of Follow_Up
            message – correctionField of Delay_Resp message]/2
            """
            t4 = (ptpmsg.rcvTimestampSec * (10**9) + ptpmsg.rcvTimestampNanoSec)

            self.meanPathDelay_ti = ((self.t2_arr_nanos - self.t3_egress_nanos)
                                     + (t4 - (self.t1_ts_s * (10**9)) - self.t1_ts_ns)
                                     - self.t1_corr - ptpmsg.correctionNanoseconds) / 2

            # 2019 / 8.2.2.4 currentDS.meanDelay: The data type should be TimeInterval
            self.meanDelay = self.meanPathDelay_ti

            self.PTPcorrection = abs(self.meanPathDelay_ti) / (10**9)
            # print(f"Current mean path delay (sec): {self.PTPcorrection:.09f}")

            self.network_time_ns = t4 + self.meanPathDelay_ti
            self.network_time_monotonic_ts = time.monotonic_ns()

            """
            # This Q builds a sliding avg of all MPDs.
            self.meanPathDelay_tiValues.append(mpdNanos)
            # must append, otherwise ZeroDivisionError
            self.meanPathDelay_tiMean = sum(self.meanPathDelay_tiValues)/ \
             (self.meanPathDelay_tiValues.maxlen-self.meanPathDelay_tiValues.count(0))
            print(f"self.meanPathDelay_tiMean (sec): {abs(self.meanPathDelay_tiMean)/(10**9):.09f}")
            """

            """
            derived from our clock:
            t4 = self.t3_egress_nanos + mpd - self.offsetFromMaster_ti

            from master:
            t4 = (ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec)

            diff of the above two:
            diff = (self.t3_egress_nanos + mpd - self.offsetFromMaster_ti) - \
              ((ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec)

            as our clock derived from master:
            t4 = (ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec \
                + self.offsetFromMaster_ti
            """
            if ((self.cfg & self.CFG.ShowMeanPathDelay) and (ptpmsg.sequenceID % (thinning / 10) == 0)):
                print(f"PTP-correction (sec): {self.PTPcorrection:.09f}")
                """
                origin = ptpmsg.rcvTimestampSec + (ptpmsg.rcvTimestampNanoSec/(10**9))
                         + self.PTPcorrection
                print(f"Timetamp at origin now: {origin:.09f}")
                """

            if ((self.cfg & self.CFG.ShowDELAY_RESP) and (ptpmsg.sequenceID % thinning == 0)):
                print(f"PTP320 {ptpmsg.msg_type: <12}",
                      f"srcprt-#: {ptpmsg.sourcePortNumber:05d}",
                      f"clockId: {ptpmsg.clockIdentity.hex()}",
                      f"seq-ID: {ptpmsg.sequenceID:08d}",
                      f"correctionNanosec: {ptpmsg.correctionNanoseconds:09d}",
                      f"receiveTimestamp: {ptpmsg.rcvTimestampSec}.{ptpmsg.rcvTimestampNanoSec:09d}",
                      )
        elif(isinstance(ptpmsg, PTPAnnounceMsg)):
            ptpfm = PTPForeignMaster(ptpmsg, timestampArrival)
            self.isKnownForeignMaster(ptpfm, ptpmsg, timestampArrival)
            if not (self.getPortState() == PTPPortState.INITIALIZING
                    or self.getPortState() == PTPPortState.SLAVE
                    or self.getPortState() == PTPPortState.PASSIVE
                    or self.getPortState() == PTPPortState.UNCALIBRATED):

                if(self.gmClockIdentity is None):
                    """
                    Normally, (in AirPlay) PTP masters negotiate amongst
                    themselves who leads, then only that 1 gm sends Announce.
                    In this half PTP implementation, as a CPU measure,
                    let them fight it out and then just run promoteMaster
                    directly.
                    """
                    self.promoteMaster(ptpmsg, "changeover")

            if(self.gmClockIdentity is not None and ptpmsg.hasTLVs):
                # path trace TLV path-seq in Announce (also) has GM
                """
                IEEE-1588-2019:
                16.2.3 Receipt of an Announce message
                A PTP Port of a Boundary Clock receiving an Announce message from
                 the current parent PTP Instance shall:
                a) Scan the pathSequence member of any PATH_TRACE TLV present for a value of the
                 clockIdentity field equal to the value of the defaultDS.clockIdentity member of
                 the receiving PTP Instance, that is, there is a “match.”
                b) Discard the message if the TLV is present and a match is found.
                c) Copy the pathSequence member of the TLV to the pathTraceDS.list member
                 (see 16.2.2.2.1) if the TLV is present and no match is found.
                """
                if self.gmClockIdentity in ptpmsg.tlvPathSequence:
                    self.lastAnnounceFromMasterNanos = timestampArrival
                    pass
                else:  # if self.gmClockIdentity != ptpmsg.gmClockIdentity:
                    self.compareMaster(ptpmsg)

            if ((self.cfg & self.CFG.ShowANNOUNCE) and (ptpmsg.sequenceID % thinning == 0)):
                # varianceb10 = 2**((ptpmsg.gmClockVariance - 0x8000) / 2**8)
                # varianceb2 = ((ptpmsg.gmClockVariance - 0x8000) / 2**8)
                # i.e. gmVariance = (log2(variance)*2^8)+32768
                # 0x0000 => 2^-128 | 0xFFFE => 2^127.99219
                print(f"PTP320 {ptpmsg.msg_type: <12}",
                      f"srcprt-#: {ptpmsg.sourcePortNumber:05d}",
                      f"pri1/2: {ptpmsg.prio01}/{ptpmsg.prio02}",
                      f"gmClockClass: {ClkClass(ptpmsg.gmClockClass)}",
                      f"gmClockAccuracy: {ClkAccuracy(ptpmsg.gmClockAccuracy)}",
                      # f"gmClockVariance(s): {varianceb10:.04g}",
                      # f"gmClockVariance(s): 2^{varianceb2:.04g}",
                      f"gmClockId: {ptpmsg.gmClockIdentity.hex()}",
                      f"seq-ID: {ptpmsg.sequenceID:08d}",
                      f"timeSource: {ptpmsg.timeSource}",
                      "Time:", ptpmsg.originTimestampSec)

                if(self.cfg & self.CFG.ShowTLVs):
                    print(f"PTP320  with PathTrace { [f'0x{addr.hex()}' for addr in ptpmsg.tlvPathSequence] }")
                # print(f"processingOverhead for {ptpmsg.msg_type}:{processingOverhead:.9f}")

        elif(isinstance(ptpmsg, PTPFollow_UpMsg)):
            # in Airplay(2) PreciseOriginTimestamp = device uptime.
            if(ptpmsg.sequenceID == self.syncSequenceID
               and self.gmClockIdentity is not None
               and ptpmsg.clockIdentity == self.gmClockIdentity):

                self.t1_arr_nanos = timestampArrival
                self.t1_ts_s = ptpmsg.preciseOriginTimestampSec
                self.t1_ts_ns = ptpmsg.preciseOriginTimestampNanoSec
                self.t1_corr = ptpmsg.correctionNanoseconds

                # <offsetFromMaster> = <syncEventIngressTimestamp> ─
                # <preciseOriginTimestamp> ─ <meanDelay> ─
                # <correctedSyncCorrectionField> ─ correctionField of Follow_Up
                # message

                # when iPhones deep sleep - their uptime (origintimestamp) pauses
                self.offsetFromMaster_ti = (
                    self.t2_arr_nanos
                    - ((self.t1_ts_s * (10**9)) + self.t1_ts_ns)
                    - self.meanDelay
                    - self.syncCorrection_ts  # Seems to be 0 in AP2
                    - ptpmsg.correctionNanoseconds
                )
                self.offsetFromMaster_tiValues.append(self.offsetFromMaster_ti)
                # must append otherwise ZeroDivisionError
                self.offsetFromMaster_tiMean = sum(
                    self.offsetFromMaster_tiValues) / (
                    self.offsetFromMaster_tiValues.maxlen
                    - self.offsetFromMaster_tiValues.count(0))
                # print(f"self.offsetFromMasterMean (sec): {self.offsetFromMaster_tiMean/(10**9):.09f}")

                # in two step PTP - we send a DELAY_REQ, and await its response
                # to figure out t3 and t4

                self.adjustedMaster_ts = (
                    (self.t1_ts_s * 10**9 + self.t1_ts_ns)
                    + self.meanDelay
                    + self.syncCorrection_ts
                )

                if ptpmsg.hasTLVs:
                    # Get the goods. parseTLVs will assign the variables.
                    self.parseTLVs(ptpmsg.tlvSeq)
                    if self.cumulativeScaledRateOffset != 0:
                        self.rateRatio = (
                            self.cumulativeScaledRateOffset
                            / 0x20000000000  # 1 << 41 i.e. 2^41
                            + 1
                        )
                    else:
                        self.rateRatio = 1
                    # This rateRatio is gmRateRatio: it came from the GM

                    correction = (self.meanDelay * self.rateRatio) + self.t1_corr
                    if correction > 0:
                        self.adjustedMaster_ts += correction
                    else:
                        self.adjustedMaster_ts -= correction

                    local_adjust = self.calcRateDelta(
                        m_ts=(self.t1_ts_s * 10**9 + self.t1_ts_ns),
                        s_ts=self.t2_arr_nanos
                    )

                    self.lastGmFreqChange = 1 / (
                        (self.scaledLastGmFreqChange / 0x20000000000) + 1)

                    self.masterOffset = (
                        self.t2_arr_nanos
                        - self.adjustedMaster_ts
                    )

                    # if(self.gmTimeBaseIndicator != self.gmTimeBaseIndicatorOld):
                    #     pass

                    #     # Normally, a syntonize, or SlaveState will trigger
                    #     # these assignments:
                    #     # # handle ScaledLastGmPhaseChange?
                    #     # print(f'scaledLastGmPhaseChangeM{self.scaledLastGmPhaseChangeM}')
                    #     # print(f'scaledLastGmPhaseChangeL{self.scaledLastGmPhaseChangeL}')
                    #     # self.scaledLastGmPhaseChangeM = self.cumulativeScaledRateOffset

                if ((self.cfg & self.CFG.ShowFOLLOWUP) and (ptpmsg.sequenceID % thinning == 0)):
                    # print info every nth pkt
                    print(f"PTP320 {ptpmsg.msg_type: <12}",
                          f"srcprt-#: {ptpmsg.sourcePortNumber:05d}",
                          f"clockId: {ptpmsg.clockIdentity.hex()}",
                          f"seq-ID: {ptpmsg.sequenceID:08d}",
                          f"correctionNanosec: {ptpmsg.correctionNanoseconds:09d}",
                          f"PreciseTime: {ptpmsg.preciseOriginTimestampSec}.{ptpmsg.preciseOriginTimestampNanoSec:09d}")

                    if((self.cfg & self.CFG.ShowTLVs) and ptpmsg.hasTLVs):
                        print(f"PTP320  with TLVs {ptpmsg.tlvSeq}")
                        self.parseTLVs(ptpmsg.tlvSeq)

        elif(isinstance(ptpmsg, PTPSigMsg)):
            if ((self.cfg & self.CFG.ShowSIGNALLING) and (ptpmsg.sequenceID % thinning == 0)):
                print("PTP320", ptpmsg.msg_type,
                      "sequenceID: ", ptpmsg.sequenceID,
                      "periodicity:", self.parseTSInterval(ptpmsg.logMessagePeriod),
                      )
                if((self.cfg & self.CFG.ShowTLVs) and ptpmsg.hasTLVs):
                    print(f"PTP320  with TLVs {ptpmsg.tlvSeq}")
                    self.parseTLVs(ptpmsg.tlvSeq)

    def syntonize(self):
        self.gmTimeBaseIndicator += 1
        self.firstDelta = True  # probably

    def parseTLVs(self, tlvSeq):
        for x in range(0, len(tlvSeq)):

            if tlvSeq[x][0] == TLVType.ORGANIZATION_EXTENSION:
                self.parseOrgIDTLVs(tlvSeq[x])
            # elif tlvSeq[x][0] == TLVType.PATH_TRACE:
            #     self.parsePathTraceTLV(tlvSeq[x])

    def parsePathTraceTLV(self, value):
        # Path Trace TLV: 8*N
        if(self.cfg & self.CFG.ShowTLVs):
            print(f' Path Trace: {[addr[2] for addr in value]}')

    def parseOrgIDTLVs(self, tlvEntry):
        TYP = tlvEntry[0]
        LEN = tlvEntry[1]
        OID = tlvEntry[2]
        VAL = tlvEntry[3]

        if(self.cfg & self.CFG.ShowDebug and self.cfg & self.CFG.ShowTLVs):
            print(f" Raw TLV",
                  f"Typ:{TLVType(TYP)}",
                  f"Len:{LEN:5d}",
                  f"OID:{OID.hex()}",
                  f"Val:{VAL.hex()}",
                  )

        if(LEN == 28 and OID == b'\x00\x80\xc2\x00\x00\x01'):
            self.parseFollowUpInfoTLV(VAL)
        elif(LEN == 12 and OID == b'\x00\x80\xc2\x00\x00\x02'):
            self.parseMsgIntervalReqTLV(VAL)
        # elif(LEN == 12 and OID == b'\x00\x80\xc2\x00\x00\x03'):
        #     self.parseSignalling003TLV(VAL)
        elif(LEN == 22 and OID == b'\x00\x0d\x93\x00\x00\x01'):
            # Master Clock parameters like announceInterval(?)
            self.parseApple001TLV(VAL)
        elif(LEN == 16 and OID == b'\x00\x0d\x93\x00\x00\x04'):
            # Master Clock ID
            self.parseApple004TLV(VAL)

    def parseSignalling003TLV(self, value):
        """802.1AS-2011 specific TLV in Signalling (CSN TLV):
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 46
        organizationId      | 3 | 4   <-- 00:80:c2
        organizationSubType | 3 | 7   <-- 00:00:03
        upstreamTxTime      | 12| 10
        neighborRateRatio   | 4 | 22
        neighborPropDelay   | 12| 26
        delayAsymmetry      | 12| 38

        upstreamTxTime (UScaledNs)
        neighborRateRatio (Integer32)
        neighborPropDelay (UScaledNs)
        delayAsymmetry (UScaledNs)
        CSN egress node

        This TLV is not allowed to occur before the Follow_Up information TLV (see 11.4.4.3)
        """
        # Not seen this TLV in AP2.
        pass

    def parseLDInterval(self, value):
        # Reserved: -128 -> -125 and 124 -> 126
        if value == 127:
            return 'dontSend'
        elif value == 126:
            self.pdelayReqInterval = 2**self.initialLogPdelayReqInterval
            return 'initial'
        elif value == -128:
            return 'dontChange'
        else:
            self.pdelayReqInterval = 2**value
            return self.pdelayReqInterval

    def parseTSInterval(self, value):
        if value == 127:
            return 'dontSend'
        elif value == 126:
            self.syncInterval = 2**self.initialLogSyncInterval
            return 'initial'
        elif value == -128:
            return 'dontChange'
        else:
            self.syncInterval = 2**value
            return self.syncInterval

    def parseAInterval(self, value):
        if value == 127:
            return 'dontSend'
        elif value == 126:
            self.announceInterval = 2**self.initialLogAnnounceInterval
            return 'initial'
        elif value == -128:
            return 'dontChange'
        else:
            # can verify by examining the logMessageInterval field of subsequent
            # received Announce messages.
            self.announceInterval = 2**value
            return 2 ** self.announceInterval

    def parseFollowUpInfoTLV(self, value):
        """802.1AS-2011 specific TLV in Follow_Ups:
        (Follow_Up information TLV)
        bitfield                 | Octets | TLV offset
        tlvType                   | 2 | 0   <-- 3
        lengthField               | 2 | 2   <-- 28
        organizationId            | 3 | 4   <-- 00:80:c2
        organizationSubType       | 3 | 7   <-- 00:00:01
        cumulativeScaledRateOffset| 4 | 10
        gmTimeBaseIndicator       | 2 | 14
        lastGmPhaseChange         | 12| 16
        scaledLastGmFreqChange    | 4 | 28

        int32   : cumulativeScaledRateOffset
        uint16  : gmTimeBaseIndicator
        ScaledNs: (scaled)LastGmPhaseChange
        int32   : (scaled)LastGmFreqChange:

        ScaledNs =
        uint16 Nanos Msb
        uint64 Nanos Lsb
        uint16 FracNanos

        cumulativeScaledRateOffset is equal to (rateRatio – 1.0) × (2^41),
        truncated to the next smaller signed integer, where rateRatio
        is the ratio of the frequency of the grandMaster to the frequency of
        the LocalClock entity in the time-aware system that sends the message.

        NOTE—The above scaling allows the representation of fractional frequency
        offsets in the range [–(2^–10 – 2^–41), 2^–10 – 2^–41], with
        granularity of 2^–41. This range is approximately [–9.766 × 10^–4,
        9.766 × 10^–4].

        gmTimeBaseIndicator =
        timeBaseIndicator of the ClockSource entity for the current grandmaster

        * 9.2.2.2 timeBaseIndicator (UInteger16) The timeBaseIndicator is a binary
        value that is set by the ClockSource entity. The ClockSource entity
        changes the value whenever its time base changes. The ClockSource
        entity shall change the value of timeBaseIndicator if and only if there
        is a phase or frequency change. NOTE: While the clock that supplies
        time to the ClockSource entity can be lost, i.e., the time-aware system
        can enter holdover, the ClockSource entity itself is not lost. The
        ClockSource entity ensures that timeBaseIndicator changes if the source
        of time is lost.

        lastGmPhaseChange =(time of the current GM - time of the prev GM), at
        the time that the current GM became GM. value is copied from the
        lastGmPhaseChange member of the MDSyncSend structure whose receipt
        causes the MD entity to send the Follow_Up message

        * 9.2.2.3 lastGmPhaseChange (ScaledNs) The value of lastGmPhaseChange is
        the phase change (i.e., change in sourceTime) that occurred on the most
        recent change in timeBaseIndicator. The value is initialized to 0.

        scaledLastGmFreqChange =

        fractional frequency offset of the current GM relative to the previous
        GM, at the time that the current GM became GM. or relative to itself
        prior to the last change in gmTimeBaseIndicator, multiplied by 2^41 and
        truncated to the next smaller signed integer. The value is obtained by
        multiplying the lastGmFreqChange member of MDSyncSend whose receipt
        causes the MD entity to send the Follow_Up message(see 11.2.11) by 2^41,
        and truncating to the next smaller signed Integer8

        9.2.2.4 lastGmFreqChange (Double) The value of lastGmFreqChange is the
        fractional frequency change (i.e., frequency change expressed as a pure
        fraction) that occurred on the most recent change in timeBaseIndicator.
        The value is initialized to 0.
        """
        """
        In Airplay:

        int32 cumulativeScaledRateOffset
        uint16 gmTimeBaseIndicator
        scaledNs scaledLastGmPhaseChange
        int32 scaledLastGmFreqChange

        ScaledNs (96bits) =
        uint32 Nanos Msb  # 4
        uint64 Nanos Lsb  # 8

        For example: –2.5 ns is expressed as: 0xFFFF FFFF FFFF FFFF FFFD 8000
        For example: 2.5 ns is expressed as: 0x0000 0000 0000 0000 0002 8000
        """
        self.cumulativeScaledRateOffset = bigint(value[0:4])
        self.gmTimeBaseIndicator = bigint(value[4:6])
        self.scaledLastGmPhaseChangeM = bigint(value[6:10], True)
        self.scaledLastGmPhaseChangeL = bigint(value[10:18], True)
        self.scaledLastGmFreqChange = bigint(value[18:22])
        if(self.cfg & self.CFG.ShowTLVs):
            print(f' FollowUpTLV',
                  f'cumulativeScaledRateOffset: {self.cumulativeScaledRateOffset}',
                  f'gmTimeBaseIndicator: {self.gmTimeBaseIndicator}',
                  f'scaledLastGmPhaseChangeM: {self.scaledLastGmPhaseChangeM}',
                  f'scaledLastGmPhaseChangeL: {self.scaledLastGmPhaseChangeL}',
                  f'scaledLastGmFreqChange: {self.scaledLastGmFreqChange}',
                  )

    def parseMsgIntervalReqTLV(self, value):
        """802.1AS-2011 specific TLV in Signalling:
        targetPortIdentity (PortIdentity) (this comes before the TLV)
        The value is 0xFF. (Apple seems to use 0x00)
        (Message interval request TLV)
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 12
        organizationId      | 3 | 4   <-- 00:80:c2
        organizationSubType | 3 | 7   <-- 00:00:02
        linkDelayInterval   | 1 | 10
        timeSyncInterval    | 1 | 11
        announceInterval    | 1 | 12
        flags               | 1 | 13
        reserved            | 2 | 14

        uint8 : linkDelayInterval
        uint8 : timeSyncInterval
        uint8 : announceInterval
        uint8 : flags (== 3)
        uint16: reserved

        10.5.4.3.6 linkDelayInterval (Integer8) = log base 2 of mean time
        interval, desired by the port that sends this TLV, between successive
        Pdelay_Req messages sent by the port at the other end of the link. The
        format and allowed values of linkDelayInterval are the same as the
        format and allowed values of initialLogPdelayReqInterval, see 11.5.2.2.
        values 127, 126, and -128 are interpreted as (same for timeSync and
        announce):

        127 = stop sending
        126 = set currentX to the value of initialX
        -128= not to change the mean time interval between successive X messages.

        10.5.4.3.7 timeSyncInterval (Integer8) = log base 2 of mean time
        interval, desired by the port that sends this TLV, between successive
        time-synchronization event messages sent by the port at the other end
        of the link. The format and allowed values of timeSyncInterval are the
        same as the format and allowed values of initialLogSyncInterval, see
        10.6.2.3, 11.5.2.3, 12.6, and 13.9.2.

        10.5.4.3.8 announceInterval (Integer8) = log base 2 of mean time
        interval, desired by the port that sends this TLV, between successive
        Announce messages sent by the port at the other end of the link. The
        format and allowed values of announceInterval are the same as the
        format and allowed values of initialLogAnnounceInterval, see 10.6.2.2.

        10.5.4.3.9 flags (Octet)
        Bits 1 and 2 of the octet are defined in Table 10-14 and take on values T/F
        1 = computeNeighborRateRatio
        2 = computeNeighborPropDelay
        """
        linkDelayInterval = self.parseLDInterval(bigint(value[0:1], True))
        timeSyncInterval = self.parseTSInterval(bigint(value[1:2], True))
        announceInterval = self.parseAInterval(bigint(value[2:3], True))
        computeNeighborRateRatio = (value[3] & 0b00000001 == 1)
        computeNeighborPropDelay = (value[3] & 0b00000010 == 2)

        if(self.cfg & self.CFG.ShowTLVs):
            print(f' SignallingTLV',
                  f'linkDelayInterval: {linkDelayInterval}',
                  f'timeSyncInterval: {timeSyncInterval}',
                  f'announceInterval: {announceInterval}',
                  f'computeNeighborRateRatio: {computeNeighborRateRatio}',
                  f'computeNeighborPropDelay: {computeNeighborPropDelay}',
                  )

    """802.1AS-2011 specific TLV:
    def parseCoordSharedNetTLV(self, value):  # 802.1AS Annex E
        targetPortIdentity (PortIdentity) (this comes before the TLV)
        (Message interval request TLV)
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 46
        organizationId      | 3 | 4   <-- 00:80:c2
        organizationSubType | 3 | 7   <-- 00:00:03
        upstreamTxTime      | 12| 10
        neighborRateRatio   | 4 | 22
        neighborPropDelay   | 12| 26
        delayAsymmetry      | 12| 38

        upstreamTxTime (UScaledNs)
        neighborRateRatio (Integer32)
        neighborPropDelay (UScaledNs)
        delayAsymmetry (UScaledNs)
    """

    def parseApple001TLV(self, value):
        """ Apple specific TLV in Signalling seems to be:
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 22
        organizationId      | 3 | 4   <-- 00:0d:93
        organizationSubType | 3 | 7   <-- 00:00:01
        dataField           | N | 10  <-- where:

        # Educated guess: An Apple MsgIntervalReqTLV which suffixes Sig msgs
        uint8 : linkDelayInterval(?)
        uint8 : timeSyncInterval(?)
        uint8 : (2==wired | 3==wifi)
        uint8 : flags (== 3)
        uint32: reserved
        uint64: reserved
        """
        # Master Clock parameters like announceInterval(?)
        if(self.cfg & self.CFG.ShowTLVs):
            print(f' Apple001TLV dataBlock: {value[0:16].hex()}')

    def parseApple004TLV(self, value):
        """Apple specific TLV in Follow_Up seems to be:
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 10
        organizationId      | 3 | 4   <-- 00:0d:93
        organizationSubType | 3 | 7   <-- 00:00:04
        dataField           | N | 10  <-- where:

        8 byte clock ID (including port)
        2 bytes (reserved?)
        Note: 802.1AS mandates EUI64 with 0xFFFE in the middle.
        Apple seems to use EUI48 with PortNumber suffixed.
        """

        # This TLV does not seem mandatory: Sonos do not emit them when master.
        # The Master Clock ID, which is MAC(6)+PortNumber(2) - 8 bytes
        # 2 bytes reserved
        if(self.cfg & self.CFG.ShowTLVs):
            print(f' Apple004TLV masterClock: {value[0:8].hex()}')

    def listen(self):
        sockets = []

        for port in self.portEvent319, self.portGeneral320:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.bind(('0.0.0.0', port))
            print(f'PTP binding to 0.0.0.0:{port}')
            # server_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            # server_socket.bind(('::', port))
            # print(f'PTP binding to [::]:{port}')

            """
            if self._IPV4:
                print('PTP binding to', self._IPV4, port)
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    server_socket.bind((self._IPV4, port))
                except PermissionError:
                    server_socket.bind(('0.0.0.0', port))
                    print('[!] WARNING: Could not bind to', self._IPV4, 'which means that if '
                          'you have multiple interfaces, PTP might unexpectedly bind to '
                          'another interface (with a lower IPv4).')
                    print('[!] WARNING: Try to run with root permissions.')
                    print('[!] PTP binding to', '0.0.0.0', port)
            if self._IPV6:
                print('PTP binding to', self._IPV6, port)
                server_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                try:
                    server_socket.bind((self._IPV6, port))
                except (PermissionError):
                    server_socket.bind(('::', port))
                    print('[!] WARNING: Could not bind to', self._IPV6, 'which means that if '
                          'you have multiple interfaces, PTP might unexpectedly bind to '
                          'another interface (with a lower IPv6).')
                    print('[!] WARNING: Try to run with root permissions.')
                    print('[!] PTP binding to', '::', port)
            """
            sockets.append(server_socket)

        empty = []
        self.portStateChange(PTPPortState.LISTENING)
        while True:
            readable, writable, exceptional = select.select(sockets, empty, empty)
            timenow = time.monotonic_ns()
            for s in readable:
                (data, address) = s.recvfrom(self.RECV_BUFFER)
                # print(address, data)
                # s.sendto(client_data, client_address)
                timestampArrival = time.monotonic_ns()

                msg_type = MsgType(data[0] & 0b00001111)
                if msg_type == MsgType.SYNC:
                    ptpmsg = PTPSyncMsg(data, msg_type)
                elif msg_type == MsgType.ANNOUNCE:
                    ptpmsg = PTPAnnounceMsg(data, msg_type)
                elif msg_type == MsgType.DELAY_REQ:
                    ptpmsg = PTPDelay_RqMsg(data, msg_type)
                elif msg_type == MsgType.DELAY_RESP:
                    ptpmsg = PTPDelay_RspMsg(data, msg_type)
                elif msg_type == MsgType.FOLLOWUP:
                    ptpmsg = PTPFollow_UpMsg(data, msg_type)
                elif msg_type == MsgType.SIGNALLING:
                    ptpmsg = PTPSigMsg(data, msg_type)
                """
                # Currently unused in Airplay PTP, currently unhandled internally.
                elif msg_type == MsgType.PATH_DELAY_REQ:
                    ptpmsg = PTPPath_Delay_RqMsg(data, msg_type)
                elif msg_type == MsgType.PATH_DELAY_RESP:
                    ptpmsg = PTPPath_Delay_RspMsg(data, msg_type)
                elif msg_type == MsgType.PATH_DELAY_FOLLOWUP:
                    ptpmsg = PTPPath_Delay_Rsp_Follow_UpMsg(data, msg_type)
                elif msg_type == MsgType.MANAGEMENT:
                    ptpmsg = PTPManagementMsg(data, msg_type)
                """

                # ptpmsg = PTPMsg(data)
                self.processingOverhead = time.monotonic_ns() - timestampArrival
                # just bake overhead into timestampArrival
                timestampArrival += self.processingOverhead

                delay_req = self.handlemsg(ptpmsg, address, timestampArrival, self.processingOverhead)
                if delay_req is not None:
                    s.sendto(delay_req, address)
            """
            9.2.6.12 ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES
            Each protocol engine shall support a timeout mechanism defining the
            <announceReceiptTimeoutInterval>, with a value of portDS.announceReceiptTimeout
            multiplied by the announceInterval (see 7.7.3.1).
            The ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES event occurs at the expiration of this timeout
            plus a random number uniformly distributed in the range (0,1) announceIntervals.
            """
            if (self.gmClockIdentity is not None and ((timenow - self.lastAnnounceFromMasterNanos) * 10**-9)
               > (self.announceReceiptTimeout * (
                  self.announceInterval + (random.randrange(2) * self.announceInterval)))):
                self.gmClockIdentity = None
                print('Announce Timeout')
                self.portStateChange(PTPPortState.LISTENING)
                # alt self.portStateChange(PTPPortState.MASTER)
            if (self.gmClockIdentity is not None and ((timenow - self.lastSyncFromMasterNanos) * 10**-9)
               > (self.syncReceiptTimeout)):
                self.gmClockIdentity = None
                print('Sync Timeout')
                self.portStateChange(PTPPortState.LISTENING)

        for s in sockets:
            s.close()

    def get_ptp_master_correction(self):
        # Gets the current MPD applied to master
        return self.PTPcorrection

    def get_ptp_master_nanos(self):
        # returns locally adjusted (AirPlay) PTP Master Timestamp in nanos
        return self.network_time_ns + (time.monotonic_ns() - self.network_time_monotonic_ts)

    def reader(self, conn):
        try:
            while True:
                if conn.poll(None):
                    if(conn.recv() == 'get_ptp_master_correction'):
                        conn.send(self.get_ptp_master_correction())
                    if(conn.recv() == 'get_ptp_master_nanos'):
                        conn.send(self.get_ptp_master_nanos())

        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
        finally:
            conn.close()

    def run(self, p_input):
        p = threading.Thread(target=self.listen)
        # p.daemon = True #triggers nice python crash :D
        p.start()

        reader_p = threading.Thread(target=self.reader, args=((p_input),))
        # reader_p.daemon = True #must be True or shutdown hangs here when in pure thread mode
        reader_p.start()

    @staticmethod
    def spawn(if_mac=None, IFEN=None, IPV4=None, IPV6=None, p_flags=0):
        print('got flags', p_flags)
        PTPinstance = PTP(if_mac, IFEN, IPV4, IPV6, p_flags)

        p_output, p_input = multiprocessing.Pipe()

        p = multiprocessing.Process(target=PTPinstance.run, args=(p_input,))
        p.start()

        return p, p_output
