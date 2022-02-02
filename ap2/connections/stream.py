import multiprocessing

from .control import Control
from .audio import AudioRealtime, AudioBuffered
from .stream_connection import StreamConnection


class Stream:

    # TIMING_REQUEST = 82
    # TIMING_REPLY = 83
    # TIME_SYNC = 84
    # RETRANSMIT_REQUEST = 85
    # RETRANSMIT_REPLY = 86
    REALTIME = 96
    BUFFERED = 103

    def __init__(self, stream, addr, port=0, buff_size=0, shared_key=None, isDebug=False, aud_params=None):
        # self.audioMode = stream["audioMode"] # default|moviePlayback
        self.isDebug = isDebug
        self.addr = addr
        self.port = port
        self.audio_connection = None
        self.initialized = False

        self.data_port = 0
        self.data_proc = None

        self.control_port = 0
        self.control_proc = None

        self.shared_key = shared_key
        """stat fields at teardown
        ccCountAPSender
        ccCountNonAPSender
        ccCountSender
        """
        # type should always be present
        self.streamtype = stream["type"]
        # A uint64:
        self.streamConnectionID = stream["streamConnectionID"] if "streamConnectionID" in stream else None
        # A boolean:
        self.supportsDynamicStreamID = stream["supportsDynamicStreamID"] if "supportsDynamicStreamID" in stream else None
        # bit 59 is enabled:
        # Array
        if 'streamConnections' in stream:
            self.streamConnections = []
            for sc in stream["streamConnections"]:
                self.streamConnections.append(StreamConnection(sc))

        if self.streamtype == Stream.REALTIME or self.streamtype == Stream.BUFFERED:
            self.control_port, self.control_proc = Control.spawn(self.isDebug)
            self.audio_format = stream["audioFormat"]
            """ ct: 0x1 = PCM, 0x2 = ALAC, 0x4 = AAC_LC, 0x8 = AAC_ELD. largely implied by audioFormat """
            self.compression = stream["ct"]
            self.session_key = stream["shk"] if "shk" in stream else b"\x00" * 32
            self.spf = stream["spf"]
            self.buff_size = buff_size

        if self.streamtype == Stream.REALTIME:
            self.session_iv = stream["shiv"] if "shiv" in stream else None
            self.server_control = stream["controlPort"]
            """ Run receiver with bit 13/14 and no bit 25, it's RSA in ANNOUNCE. Sender assumes you are an
            airport with only 250msec buffer, so min/max are absent from SDP. Support FP2? """
            self.latency_min = stream["latencyMin"]
            self.latency_max = stream["latencyMax"]
            """ Define a small buffer size - enough to keep playback stable
            (11025//352) ≈ 0.25 seconds. Not 'realtime', but prevents jitter well.
            """
            buffer = (self.latency_max // self.spf) + 1
            self.data_port, self.data_proc, self.audio_connection = AudioRealtime.spawn(
                self.addr,
                self.session_key, self.session_iv,
                self.audio_format, buffer,
                self.spf,
                self.streamtype,
                isDebug=self.isDebug,
                aud_params=None,
            )
            self.descriptor = {
                'type': self.streamtype,
                'controlPort': self.control_port,
                'dataPort': self.data_port,
                'audioBufferSize': self.buff_size,
            }
        elif self.streamtype == Stream.BUFFERED:
            buffer = (buff_size // self.spf) + 1
            iv = None
            self.data_port, self.data_proc, self.audio_connection = AudioBuffered.spawn(
                self.addr,
                self.session_key, iv,
                self.audio_format, buffer,
                self.spf,
                self.streamtype,
                isDebug=self.isDebug,
                aud_params=None,
            )
            self.descriptor = {
                'type': self.streamtype,
                'controlPort': self.control_port,
                'dataPort': self.data_port,
                # Reply with the passed buff size, not the calculated array size
                'audioBufferSize': self.buff_size,
            }

        self.initialized = True

    def isAudio(self):
        return self.streamtype == Stream.BUFFERED or self.streamtype == Stream.REALTIME

    def isInitialized(self):
        return self.initialized

    def getStreamType(self):
        return self.streamtype

    def getControlPort(self):
        return self.control_port

    def getControlProc(self):
        return self.control_proc

    def getDataPort(self):
        return self.data_port

    def getDataProc(self):
        return self.data_proc

    def getAudioConnection(self):
        return self.audio_connection

    def getSummaryMessage(self):
        msg = f'[+] type {self.getStreamType()}: '
        if self.getControlPort() != 0:
            msg += f'controlPort={self.getControlPort()} '
        if self.getDataPort() != 0:
            msg += f'dataPort={self.getDataPort()} '
        return msg

    def getDescriptor(self):
        return self.descriptor

    def teardown(self):
        if self.streamtype == Stream.REALTIME or self.streamtype == Stream.BUFFERED:
            if self.control_proc:
                self.control_proc.terminate()
                self.control_proc.join()
            self.data_proc.terminate()
            self.data_proc.join()
            self.audio_connection.close()
