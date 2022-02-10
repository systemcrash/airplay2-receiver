from biplist import readPlistFromString, writePlistToString
from enum import IntFlag
""" with pyatv parts by pierre @postlund, maker of pyatv """
"""
from pyatv.protocols.mrp import protobuf
"""


class SupportedCommands(IntFlag):
    """ these are arbitrary values """
    empty = 0
    pause = 1
    play = 1 << 1
    playpause = 1 << 2
    nexttrack = 1 << 3
    previoustrack = 1 << 4
    shuffletoggle = 1 << 5
    repeattoggle = 1 << 6
    volumeup = 1 << 7
    volumedown = 1 << 8
    volumectrl = 1 << 9
    progress = 1 << 10
    rating = 1 << 20
    playmorelikethis = 1 << 21
    playlesslikethis = 1 << 22
    scrub = 1 << 24


class Cmd(int):
    """ these are defined by Apple """
    Play = 0
    Pause = 1
    PlayPause = 2
    Stop = 3
    NextTrack = 4
    PreviousTrack = 5
    ShuffleMode = 6
    RepeatMode = 7
    VolumeUp = 8
    VolumeDown = 9
    Unknown10 = 10
    Unknown17 = 17  # Intervals
    Unknown18 = 18  # Intervals
    Unknown19 = 19
    Rating = 20
    PlayMoreLikeThis = 21
    PlayLessLikeThis = 22
    Scrub = 24
    Unknown25 = 25  # RepeatModeA
    Unknown26 = 26  # RepeatModeB
    Unknown34 = 34
    PlaybackQueueTypesA = 122
    PlaybackQueueTypesB = 125
    Unknown129 = 129
    Unknown130 = 130
    Unknown131 = 131
    Unknown132 = 132
    Unknown134 = 134
    QueueEndAction135 = 135
    Unknown25001 = 25001
    Unknown25010 = 25010
    Unknown25050 = 25050


class MRNowPlayingInfo():
    # bit 50 is enabled; info comes in via bplist
    def __init__(self, command):
        _type = 'type'
        uMRNPI = 'updateMRNowPlayingInfo'
        params = 'params'
        applyTS = 'applyTS'
        npitxt = 'npi-text'

        npia = 'kMRMediaRemoteNowPlayingInfoArtist'
        npiai = 'kMRMediaRemoteNowPlayingInfoArtworkIdentifier'
        npiawdw = 'kMRMediaRemoteNowPlayingInfoArtworkDataWidth'
        npiawdh = 'kMRMediaRemoteNowPlayingInfoArtworkDataHeight'
        npiawmt = 'kMRMediaRemoteNowPlayingInfoArtworkMIMEType'
        npiawd = 'kMRMediaRemoteNowPlayingInfoArtworkData'
        npicikct = 'kMRMediaRemoteNowPlayingCollectionInfoKeyCollectionType'
        npici = 'kMRMediaRemoteNowPlayingInfoCollectionInfo'
        npiciid = 'kMRMediaRemoteNowPlayingInfoContentItemIdentifier'
        npid = 'kMRMediaRemoteNowPlayingInfoDuration'
        npidpbr = 'kMRMediaRemoteNowPlayingInfoDefaultPlaybackRate'
        npiet = 'kMRMediaRemoteNowPlayingInfoElapsedTime'
        npig = 'kMRMediaRemoteNowPlayingInfoGenre'
        npiial = 'kMRMediaRemoteNowPlayingInfoIsAlwaysLive'
        npimt = 'kMRMediaRemoteNowPlayingInfoMediaType'
        npipbr = 'kMRMediaRemoteNowPlayingInfoPlaybackRate'
        npiqi = 'kMRMediaRemoteNowPlayingInfoQueueIndex'
        npit = 'kMRMediaRemoteNowPlayingInfoTitle'
        npitqc = 'kMRMediaRemoteNowPlayingInfoTotalQueueCount'
        npits = 'kMRMediaRemoteNowPlayingInfoTimestamp'
        npiuin = 'kMRMediaRemoteNowPlayingInfoUserInfo'
        npiuid = 'kMRMediaRemoteNowPlayingInfoUniqueIdentifier'
        mP = 'mergePolicy'
        """
        {'type': uMRNPI, 'params':
        {'applyTS': 4170223053, 'type': npitxt, 'params':
        {npid: 5843.121632653061, npit: 'Vol 13 (Unstoppable)', npipbr: 0.0,
        npitqc: 1, npiuin: {'libEligible': True, 'abtr': 0, 'lcd': 0, 'sfid': '143456-2,29', 'sotr': 0, 'endT': 5843.121632653061, 'mzar':
        {'spzs': False, 'spze': False, 'type': 9, 'name': 'KosKhol'}, 'mzpr': 18}, npimt: 'MRMediaRemoteMediaTypeMusic',
        npici: {npicikct: 'kMRMediaRemoteNowPlayingCollectionInfoCollectionTypeAlbum'},
        npits: datetime.datetime.now(), npig: 'Kizomba Urban', npiqi: 0,
        npiial: False, npia: 'D&L SOULRHYTHM', npidpbr: 1.0, npiet: 55.418503196,
        npiciid: 'F8zIbq16TDOLkZRPw5p0hA∆wiRbwsO1SdymF4XvoWF91w',
        npiuid: 7788691735267902265}, mP: 'update'}}
        """

        if params in command and _type in command and command[_type] == uMRNPI:
            # if applyTS in command[params]:
            #     print(applyTS, ':', command[params][applyTS])
            if params in command[params]:
                for k, v in command[params][params].items():
                    print(k, ':', v) if not k == npiawd else ''
            # if _type in command[params]:
            #     print(_type, ':', command[params][_type])
            # if mP in command[params]:
            #     print(mP, ':', command[params][mP])


class MediaCommandParser():
    def __init__(self, command):
        params = 'params'
        data = 'data'
        kciek = 'kCommandInfoEnabledKey'
        kcick = 'kCommandInfoCommandKey'
        kciok = 'kCommandInfoOptionsKey'
        mrscfs = 'mrSupportedCommandsFromSender'
        kMRmrciiak = 'kMRMediaRemoteCommandInfoIsActiveKey'
        kMRmrnpiad = 'kMRMediaRemoteNowPlayingInfoArtworkData'
        self.supported = 0
        self.artwork = None
        self.mrpdata = None
        self.mrpreply = b'\x00\x00\x00Jrply\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01aU\xc3\xe0\x00\x00\x00\x00bplist00\xd0\x08\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t'

        if params in command and mrscfs in command[params]:
            for cmdkey in command[params][mrscfs]:
                cmd = readPlistFromString(cmdkey)
                if cmd[kciek] and cmd[kcick] == Cmd.Play:
                    self.supported |= SupportedCommands.play
                elif cmd[kciek] and cmd[kcick] == Cmd.Pause:
                    self.supported |= SupportedCommands.pause
                elif cmd[kciek] and cmd[kcick] == Cmd.PlayPause:
                    self.supported |= SupportedCommands.playpause
                elif cmd[kciek] and cmd[kcick] == Cmd.Stop:
                    self.supported |= SupportedCommands.pause
                elif cmd[kciek] and cmd[kcick] == Cmd.NextTrack:
                    self.supported |= SupportedCommands.nexttrack
                elif cmd[kciek] and cmd[kcick] == Cmd.PreviousTrack:
                    self.supported |= SupportedCommands.previoustrack
                elif cmd[kciek] and cmd[kcick] == Cmd.ShuffleMode:
                    self.supported |= SupportedCommands.shuffletoggle
                elif cmd[kciek] and cmd[kcick] == Cmd.RepeatMode:
                    self.supported |= SupportedCommands.repeattoggle
                elif cmd[kciek] and cmd[kcick] == Cmd.VolumeUp:
                    self.supported |= SupportedCommands.volumeup
                elif cmd[kciek] and cmd[kcick] == Cmd.VolumeDown:
                    self.supported |= SupportedCommands.volumedown
                elif cmd[kciek] and cmd[kcick] == Cmd.Unknown10:
                    self.supported |= SupportedCommands.progress
                elif cmd[kciek] and cmd[kcick] == Cmd.Rating:
                    self.supported |= SupportedCommands.rating
                elif cmd[kciek] and cmd[kcick] == Cmd.PlayMoreLikeThis:
                    self.supported |= SupportedCommands.playmorelikethis
                elif cmd[kciek] and cmd[kcick] == Cmd.PlayLessLikeThis:
                    self.supported |= SupportedCommands.playlesslikethis
                elif cmd[kciek] and cmd[kcick] == Cmd.Scrub:
                    self.supported |= SupportedCommands.scrub

        if params in command and params in command[params] and mrscfs in command[params][params]:
            for item in command[params][params]:
                if kMRmrnpiad == item:
                    self.artwork = item

        if params in command and data in command[params]:
            """ MRP data comes in here; variant format """
            self.mrpdata = command[params][data]
            length, raw = read_variant(self.mrpdata)
            if len(raw) < length:
                warning("Expected %d bytes, got %d", length, len(raw))
                return

            message = raw[:length]
            data = raw[length:]

            """
            pb_msg = protobuf.ProtocolMessage()
            pb_msg.ParseFromString(message)
            print(pb_msg)
            """

    def getSupported(self):
        return '\n' + str(SupportedCommands(self.supported))

    def getArtwork(self):
        return self.artwork


def read_variant(variant):
    """Read and parse a binary protobuf variant value."""
    result = 0
    cnt = 0
    for data in variant:
        result |= (data & 0x7F) << (7 * cnt)
        cnt += 1
        if not data & 0x80:
            return result, variant[cnt:]
    raise ValueError("invalid variant")


def write_variant(number):
    """Convert an integer to a protobuf variant binary buffer."""
    if number < 128:
        return bytes([number])
    return bytes([(number & 0x7F) | 0x80]) + write_variant(number >> 7)
