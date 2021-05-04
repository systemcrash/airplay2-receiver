"""
#Simple, naïve PTP implementation in Python

# Basic listening and sync ability. Listens only to UDP unicast on ports 319+20.
# - systemcrash 2021
# Airplay only cares about *relative* sync, as does this implementation.
# No absolute or NTP references. It currently only slaves to other master clocks
# and follows the PTP election mechanism for grand masters, then syncs to those.
# This implementation also assumes subDomain is 0 (Airplay uses unicast, not multi)
# in order to simplify logic.
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
#UDP dest port: 319 for Sync, Delay_Req, Pdelay_Req, Pdelay_Resp;
#UDP dest port: 320 for other messages.
# Sources for this implementation:
# http://www.chronos.co.uk/files/pdfs/cal/TechnicalBrief-IEEE1588v2PTP.pdf
# http://ithitman.blogspot.com/2015/03/precision-time-protocol-ptp-demystified.html
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ptp.c
# https://github.com/ptpd/ptpd/tree/master/src
# https://www.nist.gov/system/files/documents/el/isd/ieee/tutorial-basic.pdf
# https://www.ieee802.org/1/files/public/docs2008/as-garner-1588v2-summary-0908.pdf
#in 2 step, we see Announce, Del_req, Del_resp, Followup, Sig, Sync


# port 319/320 UDP
#first 4 bytes of PTP packets
self.v1_compat #4 bits
self.msg_type #4 bits
#self.reserved00 #1 byte
self.ptp_version #1 byte
self.msgLength #2 bytes
self.subdomainNumber #1 byte
self.reserved01 # 1 byte
self.flags #2 bytes = 16 bits
self.correctionNanoseconds #6 bytes = 48 bits
self.correctionSubNanoseconds #2 bytes = 16 bits
self.reserved02 # 4 bytes
self.ClockIdentity #8 bytes - typically sender mac, often with fffe in the middle
self.SourcePortID #2 bytes = 16 bits
self.sequenceID # 2 bytes = 16 bits
self.control # 1 byte
self.logMessagePeriod # 1 byte
##Delay_Req message
self.originTimestampSec #6 bytes - seconds
self.originTimestampNanoSec #4 bytes - nanoseconds    
##Delay_Resp message
self.rcvTimestampSec #6 bytes - seconds
self.rcvTimestampNanoSec #4 bytes - nanoseconds
self.requestingSrcPortIdentity #8 bytes - mac address
self.requestingSrcPortID #2 bytes - port number
##Signalling message
self.targetPortIdentity #8 bytes - mac address
self.targetPortID #2 bytes - port number
self.tlvType #2 bytes
self.tlvLen #2 bytes
self.orgId #3 bytes (first half of mac)
self.orgSubType #3 bytes = 01
"""

class MsgType(enum.Enum):
    def __str__(self):
        #so when we enumerate, we only print the msg name w/o class:
        return self.name
    # 0x00-0x03 require time stamping
    SYNC                      = 0x00
    #receiver sends del_reqs message to figure out xceive delay
    DELAY_REQ                 = 0x01
    #path_del only for asymmetric routing topo
    PATH_DELAY_REQ            = 0x02
    PATH_DELAY_RESP           = 0x03
    # 0x08-0x0d do not require time stamping
    #time increment since last msg - offset
    FOLLOWUP                  = 0x08
    #sender gets del_resp to calculate RTT delay
    DELAY_RESP                = 0x09
    PATH_DELAY_FOLLOWUP       = 0x0A
    #Ann declares clock and type
    ANNOUNCE                  = 0x0B
    SIGNALLING                = 0x0C
    MANAGEMENT                = 0x0D

class GMCAccuracy(enum.Enum):
    def __str__(self):
        return self.name 
    #GM = GrandMaster
    #00-1F - reserved
    nS25                    =   0x20 #25 nanosec
    nS100                   =   0x21
    nS250                   =   0x22
    µS1                     =   0x23 #1 microsec
    µS2_5                   =   0x24
    µS10                    =   0x25
    µS25                    =   0x26
    µS100                   =   0x27
    µS250                   =   0x28
    mS1                     =   0x29 #1 millisec
    mS2_5                   =   0x2A
    mS10                    =   0x2B
    mS25                    =   0x2C
    mS100                   =   0x2D
    mS250                   =   0x2E
    S1                      =   0x2F #1 sec
    S10                     =   0x30
    GTS10                   =   0x31 #>10sec
    #32-7F reserved
    #80-FD profiles
    UNKNOWN                 =   0xFE
    RESERVED                =   0XFF

class ClkSource(enum.Enum):
    def __str__(self):
        return self.name 
    ATOMIC                  =   0X10
    GPS                     =   0x20
    TERRESTRIAL_RADIO       =   0x30
    PTP_EXTERNAL            =   0x40
    NTP_EXTERNAL            =   0x50
    HAND_SET                =   0x60
    OTHER                   =   0x90
    INTERNAL_OSCILLATOR     =   0xA0
    #F0-FE - PROFILES
    #FF - Reserved

class ClkClass(enum.Enum):
    def __str__(self):
        return self.name 
    #RESERVED 000-005
    PRIMARY_REF_LOCKED      =     6
    PRIMARY_REF_UNLOCKED    =     7
    LOCKED_TO_APP_SPECIFIC  =    13
    UNLOCKED_FR_APP_SPECIFIC=    14
    PRC_UNLOCKED_DESYNC     =    52
    APP_UNLOCKED_DESYNC     =    58
    PRC_UNLOCKED_DESYNC_ALT =   187
    APP_UNLOCKED_DESYNC_ALT =   193
    #RESERVED 194-215
    #Profiles 216-232
    #RESERVED 233-247
    DEFAULT                 =   248
    #RESERVED 249-254
    SLAVE_ONLY              =   255

class TLVType(enum.Enum):
    def __str__(self):
        return self.name
    RESERVED                    =0x0000
    #standard:
    MANAGEMENT                  =0x0001
    MANAGEMENT_ERROR_STATUS     =0x0002
    ORGANIZATION_EXTENSION      =0x0003
    #optional:
    REQUEST_UNICAST_XMISSION    =0x0004
    GRANT_UNICAST_XMISSION      =0x0005
    CANCEL_UNICAST_XMISSION     =0x0006
    ACK_CANCEL_UNICAST_XMISSION =0x0007
    #optional trace
    PATH_TRACE                  =0x0008
    #optional timescale
    ALT_TIME_OFFSET_INDICATOR   =0x0009
    #RESERVED for std TLV  000A-1FFF
    #From 2008 std:
    AUTHENTICATION              =0x2000
    AUTHENTICATION_CHALLENGE    =0x2001
    SECURITY_ASSOCIATION_UPDATE =0x2002
    CUM_FREQ_SCALE_FACTOR_OFFSE =0x2003
    #v2.1:
    #Experimental 2004-202F
    #RESERVED   2030-3FFF
    #IEEE 1588 reserved 4002-7EFF
    #Experimental 7F00-7FFF
    #Interesting 8000-8009
    PAD                         =0x8008
    AUTHENTICATIONv2            =0x8009
    #IEEE 1588  RESERVED   800A-FFEF
    #RESERVED   FFEF-FFFF

class PTPMsg:

    class MsgFlags(Flag):
        def __str__(self):
            return self.name
        Twostep = 2 #1<<1
        Unicast = 4 #1<<2

    @staticmethod
    def getTLVs(msgLen, data, start):
        #TLV = Type, Length, Value Identifier
        tlvSeq = []
        while(msgLen - start) > 0:
            tlvType = int.from_bytes(data[start  :start+2], byteorder='big')
            tlvLen  = int.from_bytes(data[start+2:start+4], byteorder='big')
            #3 byte OID + 3 byte subOID
            #V in TLV could be 8 byte or 6 byte. TLVs are even in length.
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

            """802.1AS-2011 specific TLV in Follow_Ups seems to be:
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

            
            int32   : cumulative scaledRateOffset
            uint16  : gmTimeBaseIndicator
            ScaledNs: scaledLastGmPhaseChange
            int32   : scaledLastGmFreqChange: 
            
            ScaledNs =
            uint16 Nanos Msb
            uint64 Nanos Lsb
            uint16 FracNanos

            scaledRateOffset = (rateRatio – 1.0) × (2^41), truncated to the next smaller signed 
            integer, where rateRatio is the ratio of the frequency of the grandMaster to the 
            frequency of the LocalClock entity in the time-aware system that sends the message.

            gmTimeBaseIndicator = 
            timeBaseIndicator of the ClockSource entity for the current grandmaster

            lastGmPhaseChange = 
            (time of the current GM - time of the prev GM), at the 
            time that the current GM became GM.
            value is copied from the lastGmPhaseChange member of the MDSyncSend structure whose 
            receipt causes the MD entity to send the Follow_Up message

            scaledLastGmFreqChange = 

            fractional frequency offset of the current GM relative to the previous GM, 
            at the time that the current GM became GM. or relative to itself prior to the last 
            change in gmTimeBaseIndicator, multiplied by 2^41 and truncated to the next smaller 
            signed integer. The value is obtained by multiplying the lastGmFreqChange member of 
            MDSyncSend whose receipt causes the MD entity to send the Follow_Up message 
            (see 11.2.11) by 2^41 , and truncating to the next smaller signed Integer8
            """

            """802.1AS-2011 specific TLV in Signalling seems to be:
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

            10.5.4.3.6 linkDelayInterval (Integer8)
            = log base 2 of mean time interval, desired by the port that sends this TLV, 
            between successive Pdelay_Req messages sent by the port at the other end of the link
            The format and allowed values of linkDelayInterval are the same as the format and 
            allowed values of initialLogPdelayReqInterval, see 11.5.2.2.
            values 127, 126, and –128 are interpreted as defined in Table 10-11.

            10-11
            127 = stop sending
            126 = set currentLogPdelayReqInterval to the value of initialLogPdelayReqInterval
            –128= not to change the mean time interval between successive Pdelay_Req messages.

            10.5.4.3.7 timeSyncInterval (Integer8)
            = log base 2 of mean time interval, desired by the port that sends this TLV, 
            between successive time-synchronization event messages sent by the port at the other
             end of the link. The format and allowed values of timeSyncInterval are the same as 
             the format and allowed values of initialLogSyncInterval, see 10.6.2.3, 11.5.2.3, 
             12.6, and 13.9.2.
            values 127, 126, and –128 are interpreted as defined in Table 10-12.

            10-12
            127 = stop sending
            126 = set currentLogSyncInterval to the value of initialLogSyncInterval
            -128= not to change the mean time interval between successive time- synchronization 
            event messages

            10.5.4.3.8 announceInterval (Integer8)
            = log base 2 of mean time interval, desired by the port that sends this TLV, between
             successive Announce messages sent by the port at the other end of the link. The 
             format and allowed values of announceInterval are the same as the format and 
             allowed values of initialLogAnnounceInterval, see 10.6.2.2.
            values –128, +126, and +127 are interpreted as defined in Table 10-13.

            127 = stop sending Announce messages
            126 = set currentLogAnnounceInterval to the value of initialLogAnnounceInterval
            -127= not to change the mean time interval between successive Announce messages.

            10.5.4.3.9 flags (Octet)
            Bits 1 and 2 of the octet are defined in Table 10-14 and take on values T/F
            1 = computeNeighborRateRatio
            2 = computeNeighborPropDelay
            """

            """802.1AS-2011 specific TLV in Signalling seems to be (CSN TLV):
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

            """Apple specific TLV in Signalling seems to be:
            bitfield       | Octets | TLV offset
            tlvType             | 2 | 0   <-- 3
            lengthField         | 2 | 2   <-- 22
            organizationId      | 3 | 4   <-- 00:0d:93
            organizationSubType | 3 | 7   <-- 00:00:01
            dataField           | N | 10  <-- where:
            
            uint8 : linkDelayInterval
            uint8 : timeSyncInterval
            uint8 : announceInterval
            uint8 : flags (== 3)
            uint16: reserved?
            12 bytes extra - wooh!
            
            """

            """Apple specific TLV in (IPv6) Follow_Up seems to be:
            bitfield       | Octets | TLV offset
            tlvType             | 2 | 0   <-- 3
            lengthField         | 2 | 2   <-- 10
            organizationId      | 3 | 4   <-- 00:0d:93
            organizationSubType | 3 | 7   <-- 00:00:04
            dataField           | N | 10  <-- where:
            
            8 byte clock ID (including port)
            2 bytes (reserved?)
            """

            if   tlvType == 3: #org specific
                if  (tlvLen % 12 == 0): #OID+sID+6 bytes
                    tlvUnitSize = 12 #bytes
                elif(tlvLen % 14 == 0): #OID+sID+8 bytes
                    tlvUnitSize = 14 #bytes
                elif(tlvLen % 22 == 0): #OID+sID+(2x8) bytes(?)
                    tlvUnitSize = 22
                tlvRecordAmt = int(tlvLen / tlvUnitSize) #OID+sub+8 bytes
                # tlvSeq = [[None for c in range(3)] for r in range(tlvRecordAmt)]

                #Usually 00:80:c2:00:00:01 within FOLLOWUP
                #Apple: 00:0d:93 sub: 00:00:04 => meaning: defined by Apple. 
                # https://hwaddress.com/mac-address-range/00-0D-93-00-00-00/00-0D-93-FF-FF-FF/
                #evidently contains clockID(mac)+port
                for x in range(0,tlvRecordAmt):
                    if (tlvUnitSize-6)%8 == 0: 
                        #'one-liner' to split into an array of 8 byte segments. Evil >:) :
                        tlvData = [int.from_bytes(data[start+10+(x*tlvUnitSize)+b:start+10+(x*tlvUnitSize)+b+8], 
                            byteorder='big') for b in range(0, tlvUnitSize-6, 8)]
                    else:
                        tlvData = int.from_bytes(data[start+10+(x*tlvUnitSize):start+4+tlvLen+(x*tlvUnitSize)], 
                            byteorder='big')
                    
                    tlvSeq.append(
                        [ 
                        tlvType,
                        #OID+subOID:
                        int.from_bytes(data[start+ 4+(x*tlvUnitSize):start+10+(x*tlvUnitSize)], byteorder='big'),
                        tlvData ]
                        )


            elif tlvType == 8: #PATH_TRACE
                """
                while it may be possible to have Path and other TLV types together, best for now
                to keep their handling and return separate. Have not seen such a combination yet.
                1588-2019: 16.2.5 PATH_TRACE TLV specification
                The PATH_TRACE TLV format shall be as specified in Table 115.
                bitfield       | Octets | TLV offset
                tlvType             | 2 | 0
                lengthField         | 2 | 2
                pathSequence        | 8N| 4

                N is equal to stepsRemoved+1 (see 10.5.3.2.6). The size of the pathSequence array 
                increases by 1 for each time-aware system that the Announce information traverses.
                """
                tlvUnitSize = 8 #bytes
                tlvRecordAmt = int(tlvLen / tlvUnitSize)
                #https://blog.meinbergglobal.com/2019/12/06/tlvs-in-ptp-messages/
                tlvPathSequence = [None] * tlvRecordAmt
                for x in range(0,tlvRecordAmt):
                    tlvPathSequence[x] = \
                    int.from_bytes(data[start+ 4+(x*tlvUnitSize):start+ 4+tlvUnitSize+(x*tlvUnitSize)], byteorder='big')
                    # print(tlvPathSequence[x])
                return tlvPathSequence

            #still in the while loop
            start += tlvLen + 4 #4 byte TLV header
        return tlvSeq if len(tlvSeq) > 0 else None


    def __init__(self, data):
        # self.v1_compat = (data[0] & 0b00010000) >> 4
        self.msg_type  = MsgType(data[0] & 0b00001111) #) >> 0
        # self.ptp_version= data[1] & 0b00001111 #) >> 0
        #data[2] is 1 Reserved byte
        self.msgLength = \
        int.from_bytes(data[2:4], byteorder='big')
        if len(data) == self.msgLength:
            # domain: 0 = default | 1 = alt 1 | 3 = alt 3 | 4-127, user defined. 
            self.subdomainNumber = data[4]
            msgFlagsA = \
            int.from_bytes(data[6:7], byteorder='big')
            # msgFlagsB = \
            # int.from_bytes(data[7:8], byteorder='big')
            # self.msgFlags = self.getMsgFlags(msgFlagsA, msgFlagsB)
            self.msgFlags = PTPMsg.MsgFlags(msgFlagsA)
            """
            Semantics dictate that correction is always ZERO for
            -Announce
            -Signaling
            -PTP mgmt
            """
            self.correctionNanoseconds = \
            int.from_bytes(data[8:14], byteorder='big')
            #unlikely we will ever deal with subNanoSec or ever be accurate in Python
            # self.correctionSubNanoseconds = \
            # int.from_bytes(data[14:16], byteorder='big')
            #data[16:20][0] is 4 Reserved bytes
            self.clockIdentity = \
            int.from_bytes(data[20:28], byteorder='big')
            #SrcPortID = ID for the sending address, where each IP may have a diff one, or same.
            self.sourcePortID = \
            int.from_bytes(data[28:30], byteorder='big')
            self.sequenceID = \
            int.from_bytes(data[30:32], byteorder='big')
            #unnecessary - from ptpv1:
            #self.control    =   data[32]
            #logMessagePeriod / Interval: for Sync, Followup, Del_resp: unicast = 0x7F
            #multicast = log2(interval between multicast messages)
            # y = log2(x) => if lMP = -2, x = 0.25 sec i.e. send 4 Sync every second. 
            # -3 => 8 per second. 
            #Sync: -7 -> 1 (128/sec -> 1 per 2 sec)
            #Ann : -3 -> 3 (8/sec   -> 1 per 8 sec)
            #Delay_Resp: def -4 (16/sec) | -7 -> 6 (128/sec -> 1 per 64 sec)
            self.logMessagePeriod = data[33]
            if( (self.msg_type == MsgType.SYNC ) or \
                (self.msg_type == MsgType.ANNOUNCE ) or \
                (self.msg_type == MsgType.DELAY_REQ )):
                self.originTimestampSec = \
                int.from_bytes(data[34:40], byteorder='big')
                self.originTimestampNanoSec = \
                int.from_bytes(data[40:44], byteorder='big')
                if( self.msg_type == MsgType.ANNOUNCE ):
                    # self.originCurrentUTCOffset = int.from_bytes(data[44:46], byteorder='big')
                    #skip 1 reserved byte
                    #GM determined by (lower = better): 
                    # prio1 < Class < Accuracy < Variance < prio2 < Ident(mac)
                    self.prio01 = data[47]
                    #ClockClass = Quality Level (QL)
                    self.gmClockClass =    data[48]
                    self.gmClockAccuracy = data[49]
                    #variance: lower = better. Based on Allan Variance / Sync intv
                    #PTP variance is equal to Allan variance multiplied by (τ^2)/3, 
                    #where τ is the sampling interval
                    self.gmClockVariance = \
                    int.from_bytes(data[50:52], byteorder='big')
                    self.prio02 = data[52]
                    self.gmClockIdentity = \
                    int.from_bytes(data[53:61], byteorder='big')
                    self.localStepsRemoved = \
                    int.from_bytes(data[61:63], byteorder='big')
                    self.timeSource = data[63]
                    tlvStart = 64
                    self.hasTLVs = (self.msgLength - tlvStart) > 0
                    if self.hasTLVs:
                        self.tlvPathSequence = self.getTLVs(self.msgLength, data, tlvStart)

                    """
                    #TLV = Type, Length, Value Identifier
                    self.tlvType = int.from_bytes(data[64:66], byteorder='big')
                    #https://blog.meinbergglobal.com/2019/12/06/tlvs-in-ptp-messages/
                    if(self.tlvType==8): #PATH TRACE TLV
                        self.tlvLen = int.from_bytes(data[66:68], byteorder='big')
                        tlvRecordAmt = int(self.tlvLen / 8)
                        self.tlvPathSequence = [None] * tlvRecordAmt
                        for x in range(0,tlvRecordAmt):
                            self.tlvPathSequence[x] = \
                            int.from_bytes(data[68+(x*8):76+(x*8)], byteorder='big')
                    """

            elif( MsgType(self.msg_type) == MsgType.DELAY_RESP ):
                self.rcvTimestampSec = \
                int.from_bytes(data[34:40], byteorder='big')
                self.rcvTimestampNanoSec = \
                int.from_bytes(data[40:44], byteorder='big')
                self.requestingSrcPortIdentity = \
                int.from_bytes(data[44:52], byteorder='big') #mac+port
                self.requestingSrcPortID = \
                int.from_bytes(data[52:54], byteorder='big') #ID
            elif( MsgType(self.msg_type) == MsgType.FOLLOWUP ):
                tlvStart = 44
                self.hasTLVs = (self.msgLength - tlvStart) > 0
                self.preciseOriginTimestampSec = \
                int.from_bytes(data[34:40], byteorder='big')
                self.preciseOriginTimestampNanoSec = \
                int.from_bytes(data[40:44], byteorder='big')

                #in Airplay2 apple products, followups have tlvs (but we don't need them)
                #e.g. [OID, sub, 6 byte ID][OID, sub, 6 byte ID][OID, sub, 6 byte ID]
                # then tlvType, tlvLen. Keep going until msgLength.
                # Remember: OID+sub determine length...
                if self.hasTLVs:
                    self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)

                """
                    tlvType = \
                    int.from_bytes(data[44:46], byteorder='big')
                    tlvLen = \
                    int.from_bytes(data[46:48], byteorder='big')
                    #3 byte OID + 3 byte subOID
                    #V could be 8 byte or 6 byte.
                    tlvRecordAmt = int(tlvLen / 14) #OID+sub+8 bytes
                    self.tlvSeq = [[None for c in range(3)] for r in range(tlvRecordAmt)]
                    # self.tlvPathSequence = "0x%x" % struct.unpack(">Q", data[48:56])[0]
                    for x in range(0,tlvRecordAmt):
                        #Usually 00:80:c2:00:00:01
                        self.tlvSeq[x][0] = tlvType
                        # self.tlvSeq[x][1] = tlvLen
                        self.tlvSeq[x][1] = \
                        int.from_bytes(data[48+(x*14):54+(x*14)], byteorder='big') #OID+subOID
                        self.tlvSeq[x][2] = \
                        int.from_bytes(data[54+(x*14):62+(x*14)], byteorder='big') #8 byte ID (mac)

                    tlvStart += tlvLen + 4 #4 byte TLV header
                while(self.msgLength - tlvStart) > 0:
                    tlvType     =   int.from_bytes(data[tlvStart+0:tlvStart+ 2], byteorder='big')
                    tlvLen      =   int.from_bytes(data[tlvStart+2:tlvStart+ 4], byteorder='big')
                    tlvExtraOID =   int.from_bytes(data[tlvStart+4:tlvStart+10], byteorder='big') #OID+subOID
                    #Apple: 00:0d:93 sub: 00:00:04 => meaning: defined by Apple. 
                    # https://hwaddress.com/mac-address-range/00-0D-93-00-00-00/00-0D-93-FF-FF-FF/
                    #evidently contains clockID(mac)+port
                    if tlvExtraOID & 0x000d93000004:
                        adjust = (tlvLen - 6)+10
                        tlvExtraData = int.from_bytes(data[tlvStart+10:tlvStart+adjust], byteorder='big')
                        # print( tlvType, tlvLen, "0x%012x"% tlvExtraOID, "0x%016x"% tlvExtraData )
                        self.tlvSeq.append([ tlvType, tlvExtraOID, tlvExtraData ])
                    tlvStart += tlvLen + 4
                """

            elif( MsgType(self.msg_type) == MsgType.SIGNALLING ):
                tlvStart = 44
                self.hasTLVs = (self.msgLength - tlvStart) > 0
                self.targetPortIdentity = \
                int.from_bytes(data[34:42], byteorder='big')
                self.targetPortID = \
                int.from_bytes(data[42:44], byteorder='big')
                if self.hasTLVs:
                    self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)


class PTPMaster:
    def __init__(self):
        #Defaults are worst case.
        self.prio01 = 255
        self.gmClockClass = 255 #slave only
        self.gmClockAccuracy = 0xFF
        self.gmClockVariance = 0xFFFF
        self.prio02 = 255
        self.gmClockIdentity = 0xFFFFFFFFFFFFFFFF

    def __init__(self, data):
        self.prio01 = data.prio01
        self.gmClockClass = data.gmClockClass
        self.gmClockAccuracy = data.gmClockAccuracy
        self.gmClockVariance = data.gmClockVariance
        self.prio02 = data.prio02
        self.gmClockIdentity = data.gmClockIdentity

    def __lt__(self, other):
        if not isinstance(other, PTPMaster):
            return False
        if self.prio01 < other.prio01:
            return True
        if self.gmClockClass < other.gmClockClass:
            return True
        if self.gmClockAccuracy < other.gmClockAccuracy:
            return True
        if self.gmClockVariance < other.gmClockVariance:
            return True
        if self.prio02 < other.prio02:
            return True
        if self.gmClockIdentity < other.gmClockIdentity:
            return True
        return False
    def __eq__(self, other):
        if not isinstance(other, PTPMaster):
            return False
        return self.prio01 == other.prio01 and \
            self.gmClockClass == other.gmClockClass and \
            self.gmClockAccuracy == other.gmClockAccuracy and \
            self.gmClockVariance == other.gmClockVariance and \
            self.prio02 == other.prio02 and \
            self.gmClockIdentity == other.gmClockIdentity

class PTPForeignMaster:
    def __init__(self):
        self.sourcePortID = {}
        self.announceAmount = 0
    def __init__(self, data, arrival):
        self.sourcePortID = {data.gmClockIdentity, data.sourcePortID}
        self.announceAmount = 0
        self.mostRecentAnnounceMessage = data
        self.mraArrivalNanos = arrival
    def inc(self):
        self.announceAmount += 1
    def setMostRecentAMsg(self, data):
        self.mostRecentAnnounceMessage = data
        self.inc()
    def getAnnounceAmt(self):
        return self.announceAmount
    def getArrivalNanos(self):
        return self.mraArrivalNanos
    def getMostRecentAMsg(self):
        return self.mostRecentAnnounceMessage
    def __lt__(self, other):
        return PTPMaster( self.getMostRecentAMsg() ) <  PTPMaster( other.getMostRecentAMsg() )
    def __gt__(self, other):
        return PTPMaster( self.getMostRecentAMsg() ) >  PTPMaster( other.getMostRecentAMsg() )
    def __eq__(self, other):
        return PTPMaster( self.getMostRecentAMsg() ) == PTPMaster( other.getMostRecentAMsg() )
        # return self.sourcePortID == other.sourcePortID #also works

class PTPPortState(enum.Enum):
    def __str__(self):
        #so when we enumerate, we only print the msg name w/o class:
        return self.name
    #PRE_MASTER
    #MASTER
    INITIALIZING, \
    LISTENING, \
    PASSIVE, \
    UNCALIBRATED, \
    SLAVE = range(5)
    #no code yet to run as MASTER

class PTP():
    
    def __init__(self, net_interface):
        self.portEvent319 = 319#Sync msgs / Event Port
        self.portGeneral320 = 320 #Followup msgs / General port
        self.gm = None
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
        self.QLength = 30
        self.offsetFromMasterNanos = 0
        self.offsetFromMasterNanosMean = 0
        #deque = O(1) perf
        self.offsetFromMasterNanosValues = deque([0]*self.QLength, maxlen=self.QLength)
        self.meanPathDelayNanos = 0 #bi-directional
        self.meanPathDelayNanosMean = 0 #mean of several bi-di results
        self.meanPathDelayNanosValues = deque([0]*self.QLength, maxlen=self.QLength)
        self.processingOverhead = 0
        self.syncSequenceID = 0
        self.useMasterPromoteAlgo = True
        #add 2 empty bytes for 'PTP Port' to end of mac:
        self.net_interface = net_interface << 16
        self.net_interface_bytes = (net_interface << 16).to_bytes(8, byteorder='big')
        self.DelayReq_PortID = 32768
        self.DelayReq_template = \
        bytearray.fromhex('1102002c00000408000000000000000000000000' \
                        '01020304050600018000000100fd00000000000000000000')
        self.DelayReq_template[20:28] = self.net_interface_bytes
        self.DelayReq_template[28:30] = self.DelayReq_PortID.to_bytes(2, byteorder='big')
        self.portStateChange(PTPPortState.INITIALIZING)
        self.PTPcorrection = 0
        self.fML = [] #<foreignMasterList> # 9.3.2.4.6 Size of <foreignMasterList> min 5
        """
        Each entry of the <foreignMasterList> contains two or three members:
        - <foreignMasterList>[].foreignMasterPortIdentity,
        - <foreignMasterList>[].foreignMasterAnnounceMessages, and optionally
        - <foreignMasterList>[].mostRecentAnnounceMessage.
        """
        self.fMTW = 4 #FOREIGN_MASTER_TIME_WINDOW = 4 announceInterval
        self.fMThr= 2 #FOREIGN_MASTER_THRESHOLD 2 Announce msg within FOREIGN_MASTER_TIME_WINDOW
        """
        announceReceiptTimeoutInterval = portDS.announceReceiptTimeout * announceInterval
        """
        self.announceReceiptTimeout = 3
        self.announceInterval = 0
        #count down nanos from last Announce - expires current GM
        self.lastAnnounceFromMasterNanos = 0



    def promoteMaster(self,ptpmsg,reason):
        self.gm = PTPMaster(ptpmsg)
        print("New GM Clock promoted: "
            f"{ptpmsg.gmClockIdentity:10x} (Prio{ptpmsg.prio01}/{ptpmsg.prio02})",
            f"reason: {reason}"
            )
        #reset cumulative mean values to 0
        self.offsetFromMasterValues = deque([0]*self.QLength, maxlen=self.QLength)
        self.meanPathDelayNanosValues = deque([0]*self.QLength, maxlen=self.QLength)        
        self.portStateChange(PTPPortState.SLAVE)
        self.announceInterval = 2** ptpmsg.logMessagePeriod

    def compareMaster(self, ptpmsg):
        #This algo promotes a new master if its properties are better than currently elected GM
        # prio1 < Class < Accuracy < Variance < prio2 < Ident(mac)
        # Lower values == "better"
        if self.gm is None:
            self.promoteMaster(ptpmsg, "reset")
        else:
            incoming = PTPMaster(ptpmsg)

            if (incoming < self.gm ) == True:
                self.promoteMaster(ptpmsg, "better GM")
                self.fML = []
            #else:
                #retain current GM

    def sendDelayRequest(self, sequenceID):
        self.DelayReq_template[30:32] = sequenceID.to_bytes(2, byteorder='big')
        return self.DelayReq_template

    def portStateChange(self, PTPPortState):
        self.portState = PTPPortState
        print(f"PTP State: {self.portState}")

    def getPortState(self):
        return self.portState

    def knownForeignMaster(self, ptpfm, ptpmsg, arrivalNanos):
        """
        Looks at our list of foreignMaster candidates and when we have enough Announce
        msgs from one, we kick off the BMCA: compareMaster()
        """
        """
        9.3.2.5 Qualification of Announce messages

        c) Unless otherwise specified by the option of 17.7, if the sender of S is a foreign 
        master F, and fewer than FOREIGN_MASTER_THRESHOLD distinct Announce messages from F 
        have been received within the most recent FOREIGN_MASTER_TIME_WINDOW interval, S 
        shall not be qualified. Distinct Announce messages are those that have different 
        sequenceIds, subject to the constraints of the rollover of the UInteger16 data type 
        used for the sequenceId field.
        ...
        d) If the stepsRemoved field of S is 255 or greater, S shall not be qualified.
        ...
        e) This specification “e” is optional. ...
        ...
        f) Otherwise, S shall be qualified.
        """
        if not ptpfm in self.fML:
            self.fML.append( ptpfm )
            #new in list means count == 0, so we skip sorting/comparing
            return False
        else:
            self.fML[self.fML.index( ptpfm )].setMostRecentAMsg(ptpmsg)
            #check previous Announce arrivalNanos
            lMP = 2**ptpmsg.logMessagePeriod #e.g. 2^-2 = 0.25 sec
            #check interarrival diff of current and stored Announce nanos is 
            # less than FOREIGN_MASTER_TIME_WINDOW * logMessagePeriod
            considerBMCA = ( (arrivalNanos - self.fML[self.fML.index( ptpfm 
                )].getArrivalNanos() ) * 10**-9 ) < (self.fMTW * lMP) # e.g. 4 * 0.25 = 1 sec
            self.fML.sort() #keep fML list sorted, and mash [0] into BMCA when time comes
            if self.fML[self.fML.index( ptpfm )].getAnnounceAmt() >= self.fMThr and \
                considerBMCA:
                #run BMCA
                self.compareMaster( self.fML[0].getMostRecentAMsg() )
            return True

    def handlemsg(self, ptpmsg, address, timestampArrival, processingOverhead):
        # print(f"entered handlemsg() with {ptpmsg.sequenceID} and {self.syncSequenceID}")
        displayTLVs = True
        displayMsgs = True
        thinning = 100 # print msg every x msgs
        #port 319
        if( ( ptpmsg.msg_type == MsgType.SYNC ) or \
            ( ptpmsg.msg_type == MsgType.DELAY_REQ ) ):

            if( ptpmsg.sequenceID % thinning == 0 ) and displayMsgs:
                print(f"PTP319 {ptpmsg.msg_type: <12}", 
               f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
               f"clockId: {ptpmsg.clockIdentity:016x}",
               f"seq-ID: {ptpmsg.sequenceID:08d}",
               f"Time: {ptpmsg.originTimestampSec}.{ptpmsg.originTimestampNanoSec:09d}",
               )
                # print(f"processingOverhead for {ptpmsg.msg_type}:{processingOverhead:.9f}")

            #were we master, here is when we would respond to DELAY_REQ with DELAY_RESP
            #upon receipt of each Sync, we should respond with DELAY_REQ with same seqID
            if MsgType(ptpmsg.msg_type) == MsgType.SYNC and \
                self.gm != None and \
                ptpmsg.clockIdentity == self.gm.gmClockIdentity:
                if ptpmsg.msgFlags.Twostep:
                    #Calculate ms_propagation_delay in FOLLOWUP
                    self.t2_arr_nanos = timestampArrival
                    self.t2_ts_s = ptpmsg.originTimestampSec
                    self.t2_ts_ns= ptpmsg.originTimestampNanoSec
                    self.syncSequenceID = ptpmsg.sequenceID
                    #assign t3 to delay_req egress timestamp
                    self.t3_egress_nanos = time.monotonic_ns()
                    return self.sendDelayRequest(self.syncSequenceID)
                # else: #PTP in airplay does not seem to bother with 1-step
                #     #iPhone PTP sends ptpmsg.originTimestamp(Nano)Sec = 0... so this won't work
                #     #1-step: must calculate t2-t1 diff here.
                #     self.t1_arr_nanos = ptpmsg.originTimestampSec + (ptpmsg.originTimestampNanoSec / 10 ** 9)
                #     self.ms_propagation_delay = t2_arr - t1_arr

        elif( ptpmsg.msg_type == MsgType.DELAY_RESP and 
            ptpmsg.requestingSrcPortIdentity == self.net_interface ):
            """
            IEEE1588-2019 Spec says:
            <meanPathDelay> = [(t2 – t1) + (t4 – t3)]/2 = [(t2 – t3) + (t4 – t1)]/2

            <meanPathDelay> = [(t2 - t3) + (receiveTimestamp of Delay_Resp message – preciseOriginTimestamp of Follow_Up message) –
            <correctedSyncCorrectionField> - correctionField of Follow_Up message – correctionField of Delay_Resp message]/2
            """
            t4 = (ptpmsg.rcvTimestampSec*(10**9) + ptpmsg.rcvTimestampNanoSec )

            self.meanPathDelayNanos = ((self.t2_arr_nanos - self.t3_egress_nanos) + \
                ( t4 - ( self.t1_ts_s*(10**9)) - self.t1_ts_ns ) - \
                self.t1_corr - ptpmsg.correctionNanoseconds)/2

            self.PTPcorrection = abs(self.meanPathDelayNanos) / (10**9)
            # print(f"Current mean path delay (sec): {self.PTPcorrection:.09f}")

            """
            self.meanPathDelayNanosValues.append(mpdNanos)
            #must append, otherwise ZeroDivisionError
            self.meanPathDelayNanosMean = sum(self.meanPathDelayNanosValues)/ \
             (self.meanPathDelayNanosValues.maxlen-self.meanPathDelayNanosValues.count(0))
            print(f"self.meanPathDelayNanosMean (sec): {abs(self.meanPathDelayNanosMean)/(10**9):.09f}")
            """

            """
            derived from our clock:
            t4 = self.t3_egress_nanos + mpd - self.offsetFromMasterNanos

            from master:
            t4 = (ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec)

            diff of the above two:
            diff = (self.t3_egress_nanos + mpd - self.offsetFromMasterNanos) - \
              ((ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec) 

            as our clock derived from master:
            t4 = (ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec \
                + self.offsetFromMasterNanos
            """
            if ptpmsg.sequenceID % (thinning / 10) == 0:
                print(f"PTP-correction (sec): {self.PTPcorrection:.09f}")
                """
                origin = ptpmsg.rcvTimestampSec + (ptpmsg.rcvTimestampNanoSec/(10**9)) +\
                 self.PTPcorrection
                print(f"Timetamp at origin now: {origin:.09f}")
                """

            if ptpmsg.sequenceID % thinning == 0 and displayMsgs:
                print(f"PTP320 {ptpmsg.msg_type: <12}",
               f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
               f"clockId: {ptpmsg.clockIdentity:016x}",
               f"seq-ID: {ptpmsg.sequenceID:08d}",
               f"correctionNanosec: {ptpmsg.correctionNanoseconds:09d}",
               f"receiveTimestamp: {ptpmsg.rcvTimestampSec}.{ptpmsg.rcvTimestampNanoSec:09d}",
               )
        elif(ptpmsg.msg_type == MsgType.ANNOUNCE ):
            ptpfm = PTPForeignMaster(ptpmsg, timestampArrival)
            if not (self.getPortState() == PTPPortState.INITIALIZING or 
                self.getPortState() == PTPPortState.SLAVE or
                self.getPortState() == PTPPortState.PASSIVE or 
                self.getPortState() == PTPPortState.UNCALIBRATED):

                if(self.gm == None):
                    #if incoming master is 'better' - were we announcing, we would stop
                    # self.fML.append( ptpfm )
                    # self.promoteMaster(ptpmsg, "reset")

                    if self.knownForeignMaster(ptpfm, ptpmsg, timestampArrival):
                        pass

                    """
                    Normally, (in AirPlay) PTP masters negotiate amongst themselves who leads, 
                     then only that 1 gm sends announce.
                    In this half PTP implementation, as a CPU measure, we can let them fight it 
                    out and then just run promoteMaster directly.
                    """
                    if not self.useMasterPromoteAlgo:
                        self.promoteMaster(ptpmsg, "changeover")
                    # else:
                    #     self.compareMaster(ptpmsg)
            if(self.gm != None):
                #path trace TLV path-seq in Announce (also) has GM
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
                if self.gm.gmClockIdentity in ptpmsg.tlvPathSequence:
                    self.lastAnnounceFromMasterNanos = timestampArrival
                    pass
                else: #if self.gm.gmClockIdentity != ptpmsg.gmClockIdentity:
                    #update fML
                    self.knownForeignMaster(ptpfm, ptpmsg, timestampArrival)
                    if not self.useMasterPromoteAlgo:
                        self.compareMaster(ptpmsg)

            if (ptpmsg.sequenceID % thinning == 0) and displayMsgs:
                #varianceb10 = 2**((ptpmsg.gmClockVariance - 0x8000) / 2**8)
                #varianceb2 = ((ptpmsg.gmClockVariance - 0x8000) / 2**8)
                #i.e. gmVariance = (log2(variance)*2^8)+32768
                #0x0000 => 2^-128 | 0xFFFF => 2^127.99
                print(f"PTP320 {ptpmsg.msg_type: <12}",
                f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
                f"pri1/2: {ptpmsg.prio01}/{ptpmsg.prio02}",
                f"gmClockClass: {ClkClass(ptpmsg.gmClockClass)}",
                f"gmClockAccuracy: {GMCAccuracy(ptpmsg.gmClockAccuracy)}",
                #f"gmClockVariance(s): {varianceb10:.04g}",
                #f"gmClockVariance(s): 2^{varianceb2:.04g}",
                f"gmClockId: {ptpmsg.gmClockIdentity:10x}",#x = heX
                f"seq-ID: {ptpmsg.sequenceID:08d}",
                #f"timeSource: {ptpmsg.timeSource}",
                "Time:", ptpmsg.originTimestampSec )

                if(displayTLVs == True):
                    print(f"PTP320  with PathTrace { [f'0x{addr:016x}' for addr in ptpmsg.tlvPathSequence] }" )
                # print(f"processingOverhead for {ptpmsg.msg_type}:{processingOverhead:.9f}")

        elif(ptpmsg.msg_type == MsgType.FOLLOWUP ): #
            #in Airplay(2) PreciseOriginTimestamp = device uptime.
            if(ptpmsg.sequenceID == self.syncSequenceID and 
                self.gm != None and
                ptpmsg.clockIdentity == self.gm.gmClockIdentity):

                self.t1_arr_nanos  = timestampArrival
                self.t1_ts_s = ptpmsg.preciseOriginTimestampSec
                self.t1_ts_ns= ptpmsg.preciseOriginTimestampNanoSec
                self.t1_corr = ptpmsg.correctionNanoseconds

                #when iPhones deep sleep - their uptime (origintimestamp) pauses...
                self.offsetFromMasterNanos = (self.t2_arr_nanos - ( (ptpmsg.preciseOriginTimestampSec * (10**9) ) +\
                        ptpmsg.preciseOriginTimestampNanoSec + ptpmsg.correctionNanoseconds ) )
                self.offsetFromMasterNanosValues.append(self.offsetFromMasterNanos)
                #must append otherwise ZeroDivisionError
                self.offsetFromMasterNanosMean = sum(self.offsetFromMasterNanosValues)/ \
                 (self.offsetFromMasterNanosValues.maxlen-self.offsetFromMasterNanosValues.count(0))
                # print(f"self.offsetFromMasterMean (sec): {self.offsetFromMasterNanosMean/(10**9):.09f}")
                
                #in two step PTP - we send a DELAY_REQ, and await its response to figure out
                #t3 and t4

                if (ptpmsg.sequenceID % thinning == 0 ) and displayMsgs:
                    #print info every nth pkt
                    print(f"PTP320 {ptpmsg.msg_type: <12}", #"z from:", address, 
                    f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
                    f"clockId: {ptpmsg.clockIdentity:10x}", #x = heX
                    f"seq-ID: {ptpmsg.sequenceID:08d}",
                    f"correctionNanosec: {ptpmsg.correctionNanoseconds:09d}",
                    f"PreciseTime: {ptpmsg.preciseOriginTimestampSec}.{ptpmsg.preciseOriginTimestampNanoSec:09d}")

                    if(hasattr(ptpmsg, 'hasTLVs') and ptpmsg.hasTLVs == True and displayTLVs == True):
                        print(f"PTP320  with TLVs {ptpmsg.tlvSeq}")
                        self.parseTLVs(ptpmsg.tlvSeq)

                        
        elif( ptpmsg.msg_type == MsgType.SIGNALLING ):
            if (ptpmsg.sequenceID % thinning == 0) and displayMsgs:
                print("PTP320", ptpmsg.msg_type, 
                    "sequenceID: ", ptpmsg.sequenceID)
                if(hasattr(ptpmsg, 'hasTLVs') and ptpmsg.hasTLVs == True and displayTLVs == True):
                    print(f"PTP320  with TLVs {ptpmsg.tlvSeq}")
                    self.parseTLVs(ptpmsg.tlvSeq)


    def parseTLVs(self, tlvSeq):
        for x in range(0,len(tlvSeq)):
            if isinstance(tlvSeq[x][2], list):
                print(f"_typ:{tlvSeq[x][0]:04x}",
                # f"len:{tlvSeq[x][1]:05d}",
                f"OID:{tlvSeq[x][1]:012x}",
                f"Val:{ [f'0x{addr:016x}' for addr in tlvSeq[x][2]] }",
                )
            else:
                print(f"_typ:{tlvSeq[x][0]:04x}",
                # f"len:{tlvSeq[x][1]:05d}",
                f"OID:{tlvSeq[x][1]:012x}",
                f"Val:{tlvSeq[x][2]:016x}",
                )
            # if(ptpmsg.tlvSeq[x][2] & 0x0F0000 == 0x60000):
            #     print(f"Interpret(?): {(ptpmsg.tlvSeq[x][2] & 0xFFFFFFFF00000000)>>32}")
            # if(ptpmsg.tlvSeq[x][2] & 0x0F0000 == 0x20000):
            #     print(f"WTF(?): {ptpmsg.tlvSeq[x][2] & 0xFFFFFFFF00000000}")


    def listen(self):
        sockets = []

        for port in range(319,321):
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.bind(('0.0.0.0', port))
            sockets.append(server_socket)

        empty = []
        self.portStateChange(PTPPortState.LISTENING)
        while True:
            readable, writable, exceptional = select.select(sockets, empty, empty)
            timenow = time.monotonic_ns()
            for s in readable:
                (data, address) = s.recvfrom(180)
                # print(address, data)
                # s.sendto(client_data, client_address)

                timestampArrival = time.monotonic_ns()
                ptpmsg = PTPMsg(data)
                self.processingOverhead = time.monotonic_ns() - timestampArrival
                #just bake overhead into timestampArrival
                timestampArrival += self.processingOverhead

                delay_req = self.handlemsg(ptpmsg, address, timestampArrival, self.processingOverhead)
                if delay_req != None:
                    s.sendto(delay_req, address)
            """
            9.2.6.12 ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES
            Each protocol engine shall support a timeout mechanism defining the 
            <announceReceiptTimeoutInterval>, with a value of portDS.announceReceiptTimeout 
            multiplied by the announceInterval (see 7.7.3.1).
            The ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES event occurs at the expiration of this timeout 
            plus a random number uniformly distributed in the range (0,1) announceIntervals.
            """
            if self.gm != None and ((timenow - self.lastAnnounceFromMasterNanos) * 10**-9) > \
             ( (self.announceInterval * (self.announceReceiptTimeout + random.randrange(2) ))):
                self.gm = None
                self.portStateChange(PTPPortState.LISTENING)
                #alt self.portStateChange(PTPPortState.MASTER)

        for s in sockets:
           s.close()

    def get_ptp_master_correction(self):
        return self.PTPcorrection

    def reader(self, conn):
        try:    
            while True:
                if conn.poll():
                    if(conn.recv() == 'gettime'):
                        conn.send( self.get_ptp_master_correction() )
            # conn.close()
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
    def spawn(net_interface):
        PTPinstance = PTP(net_interface)

        p_output, p_input = multiprocessing.Pipe()

        p = multiprocessing.Process(target=PTPinstance.run, args=(p_input,))
        p.start()

        return p, p_output
