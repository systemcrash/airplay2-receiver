from ap2.playfair import PlayFair, FairPlayAES


class Session():
    """ place to hold session information """

    def __init__(self, info=None, keymsg=None):

        self.isMultiSelectAirPlay_ = info['isMultiSelectAirPlay'] if 'isMultiSelectAirPlay' in info else False
        self.groupContainsGroupLeader_ = info['groupContainsGroupLeader'] if 'groupContainsGroupLeader' in info else False
        self.groupUUID = info['groupUUID'] if 'groupUUID' in info else None
        # HijackID
        self.HTGroupUUID = info['HTGroupUUID'] if 'HTGroupUUID' in info else None
        self.isGroupLeader_ = info['isGroupleader'] if 'isGroupleader' in info else False
        self.isRemoteControlOnly_ = info['isRemoteControlOnly'] if 'isRemoteControlOnly' in info else False
        self.isTightSyncGroupLeader_ = info['isTightSyncGroupLeader'] if 'IsTightSyncGroupLeader' in info else False
        # isGroupPlayback
        # persistentGroupSize
        self.senderSupportsRelay_ = info['senderSupportsRelay'] if 'senderSupportsRelay' in info else False
        self.sessionUUID = info['sessionUUID'] if 'sessionUUID' in info else None
        self.tightSyncUUID = info['tightSyncUUID'] if 'tightSyncUUID' in info else None
        self.timingProtocol = info['timingProtocol'] if 'timingProtocol' in info else None

        """ timeline / PTP stuff """
        self.networkTimelineAnchorNanos = None
        self.networkTimeTimelineID = None
        self.rate = None
        self.rtpClockTimeAtSender = None

        """
        Now playing info for Remote Control
        """
        self.now_remote = {}
        self.now_cover = None
        self.now_dxxp = None
        self.now_progress = None
        self.now_volume = None

        if 'eiv' in info and 'ekey' in info:
            self.aesiv = info['eiv']
            self.aeskey = info['ekey']
            self.aeskeyobj = FairPlayAES(fpaeskey=self.aeskey, aesiv=self.aesiv, keymsg=keymsg)

        if 'timingPeerInfo' in info:
            """ consists of:
            Addresses: [{IPv4, IPv6, ...}],
            ClockID: uint64,
            ClockPorts: {'guid': port},
            DeviceType: int,
            ID: 'guid',
            SupportsClockPortMatchingOverride: bool,
            """
            timingPeerInfo = info['timingPeerInfo']
        if 'timingPeerList' in info:
            """ Array of:
            [timingPeerInfo, timingPeerInfo, ...]
            """
            self.timingPeerList = []
            for tp in info['timingPeerList']:
                self.timingPeerList.append(TimingPeer(tp))

    # Timing stuff
    def getTimingPeerList(self):
        if len(self.timingPeerList) > 0:
            return self.timingPeerList

    def setRateAnchorTimePTP(self, plist):
        """ Using PTP, here is what is necessary
        * The local (monotonic system up)time in nanos (arbitrary reference)
        * The remote (monotonic system up)time in nanos (arbitrary reference)
        * (symmetric) link delay
        1. calculate link delay (PTP)
        2. get local time (PTP)
        3. calculate remote time (nanos) wrt local time (nanos) w/PTP. Now
           we know how remote timestamps align to local ones. Now these
           network times are meaningful.
        4. determine how many nanos elapsed since anchorTime msg egress.
        Note: remote monotonic nanos for iPhones stops when they sleep, though
          not when casting media.
        """
        if('networkTimeFrac' in plist and 'networkTimeSecs' in plist):
            nTSec = int(plist['networkTimeSecs'])
            nTFrac = int(plist['networkTimeFrac'])  # Units are (1/2^64)
            nTSec += ((nTFrac & 0xffffffffffffffff) * 2**-64)
            self.networkTimelineAnchorNanos = int(nTSec * 1e9)

        if('networkTimeTimelineID' in plist):
            """ should resolve to the device mac and PTP clock port """
            self.networkTimelineID = int(plist['networkTimeTimelineID'] & 0xffffffffffffffff)

        if('rtpTime' in plist):
            self.rtpClockTimeAtSender = plist['rtpTime']

        if('rate' in plist):
            """ we don't do calculations so we could keep rate as txt """
            self.rate = int(plist['rate'])

    def getTimelineInfo(self):
        return TimelineInfo(
            self.networkTimelineAnchorNanos,
            self.rtpClockTimeAtSender
        )

    def getNetworkAnchorTime(self):
        return self.networkTimelineAnchorNanos

    def getNTTLID(self):
        return self.networkTimeTimelineID

    def getRate(self):
        return self.rate

    def getTimingProtocol(self):
        return self.timingProtocol

    def isPTP(self):
        return self.timingProtocol == 'PTP'

    def getSessionUUID(self):
        return self.sessionUUID

    def getGroupUUID(self):
        return self.groupUUID

    def gCGL(self):
        return self.groupContainsGroupLeader_

    def sSR(self):
        return self.senderSupportsRelay_

    def isMSAP(self):
        return self.isMultiSelectAirPlay

    def isGL(self):
        return self.isGroupLeader_

    def isRCO(self):
        return self.isRemoteControlOnly_

    # Key stuff
    def getAESKey(self):
        return self.aeskeyobj.getAESKey()

    def getAESIV(self):
        return self.aeskeyobj.getAESIV()

    def getNowRemote(self):
        return self.now_remote

    def setNowRemote(self, _value=None):
        self.now_remote = _value

    def getNowProgress(self):
        return self.now_progress

    def setNowProgress(self, _value=None):
        self.now_progress = _value

    def getNowCover(self):
        return self.now_cover

    def setNowCover(self, _value=None):
        self.now_cover = _value

    def getNowDXXP(self):
        return self.now_dxxp

    def setNowDXXP(self, _value=None):
        self.now_dxxp = _value

    def getNowVolume(self):
        return self.now_volume

    def setNowVolume(self, _value=None):
        self.now_volume = _value


class TimelineInfo():
    """ object for passing timeline specifics e.g. to audio module """
    def __init__(self, ntlan, rctas):

        self.ntlan = int(ntlan)
        self.rctas = int(rctas)

    def networkTimelineAnchorNanos(self):
        return self.ntlan

    def rtpClockTimeAtSender(self):
        return self.rctas


class TimingPeer():
    """
    SETPEERSX sends these.
    Sender also includes these at connect time.
    """
    def __init__(self, timingPeer):
        if 'Addresses' in timingPeer:
            self.Addresses = timingPeer['Addresses']
        if 'ClockID' in timingPeer:
            self.ClockID = timingPeer['ClockID']
        if 'ClockPorts' in timingPeer:
            self.ClockPorts = timingPeer['ClockPorts']
        if 'DeviceType' in timingPeer:
            self.DeviceType = timingPeer['DeviceType']
        if 'ID' in timingPeer:
            self.ID = timingPeer['ID']
        if 'SupportsClockPortMatchingOverride' in timingPeer:
            self.SupportsClockPortMatchingOverride = timingPeer['SupportsClockPortMatchingOverride']

    def getAddresses(self):
        return self.Addresses

    def getClockID(self):
        return self.ClockID

    def getClockPorts(self):
        return self.ClockPorts

    def getDeviceType(self):
        return self.DeviceType

    def getID(self):
        return self.ID

    def supportsCPMO(self):
        return self.SupportsClockPortMatchingOverride
