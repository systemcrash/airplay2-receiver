import socket
import struct
import multiprocessing

from ..utils import get_file_logger, get_screen_logger, get_free_socket
from ..pairing.hap import HAPSocket


class RemoteControl():

    NONE = 0
    RELAY = 1  # Will be this if RemoteControlRelay flag is set
    DIRECT = 2

    MEDIA_REMOTE = '1910A70F-DBC0-4242-AF95-115DB30604E1'
    UNKNOWN1 = '2B6B4700-D998-4081-89F7-5D9AF93846E2'
    OTHER = '8186BE43-A39A-4C42-9D0E-60BDB9CE1FE3'
    UNKNOWN2 = 'A6B27562-B43A-4F2D-B75F-82391E250194'

    def __init__(
        self,
        addr=None,
        port=None,
        stream=None,
        shared_key=None,
        isDebug=False,
    ):
        super(RemoteControl, self).__init__(
            # addr,
            # port,
            # stream,
            # shared_key,
            # isDebug=isDebug,
        )

        self.isDebug = isDebug
        self.addr = addr
        self.port = port
        # TODO: one clientUUID can have multiple channelIDs open... (HomeKit)
        cID = 'channelID'
        self.clID = stream[cID] if cID in stream else None
        cTUUID = 'clientTypeUUID'
        self.cTUUID = stream[cTUUID] if cTUUID in stream else None    
        cUUID = 'clientUUID'
        self.clientUUID = stream[cUUID] if cUUID in stream else None
        sUUID = 'sessionUUID'
        self.sUUID = stream[sUUID] if sUUID in stream else None
        # controlType 1 = Relay 2 = Direct
        cT = 'controlType'
        self.cT = stream[cT] if cT in stream else None
        wDS = 'wantsDedicatedSocket'
        self.wDS = stream[wDS] if wDS in stream else None
        # Combine with shared_key(?) to encrypt the stream...?
        self.seed = stream['seed'] if 'seed' in stream else None
        self.shared_key = shared_key
        self.isDebug = isDebug

        self.socket = get_free_socket(self.addr, tcp=True)
        self.port = self.socket.getsockname()[1] if not port else 0
        level = 'DEBUG' if self.isDebug else 'INFO'
        self.logger = get_screen_logger(self.__class__.__name__, level=level)

    def serve(self, rtsp_connection):
        # This pipe is between player (read data) and server (write data)
        # receive commands from rtsp_connection
        # """
        try:
            self.logger.debug(f'getting socket: {self.socket}')
            client_socket = self.socket.accept()
            self.logger.debug(f'got client socket: {client_socket}')
            self.hap_socket = HAPSocket(client_socket, self.shared_key)  # , pkm='DATA')
            self.logger.debug('built HAPSocket')
        except OSError:
            pass
        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()
        """
        try:
            conn, addr = self.socket.accept()
            if self.isDebug:
                self.logger.debug(f"Open {self.__class__.__name__} connection from {addr[0]}:{addr[1]}")
            try:
                while True:
                    data = conn.recv(4096, socket.MSG_WAITALL)
                    # if data:
                    #     pass
                    print(data)
            except KeyboardInterrupt:
                pass
            finally:
                try:
                    if self.isDebug:
                        os.remove(self.file)
                except OSError:
                    pass
                conn.close()
                if self.isDebug:
                    self.logger.debug(f"Close connection from {addr[0]}:{addr[1]}")
            # self.socket.close()
        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
        finally:
            self.socket.close()
            if self.isDebug:
                self.logger.debug(f"Closed listen on {self.addr}:{self.port}")
        # """
    @classmethod
    def spawn(
        cls,
        addr=None,
        port=None,
        stream=None,
        shared_key=None,
        isDebug=False
    ):
        remote = cls(
            addr,
            port,
            stream,
            shared_key,
            isDebug,
        )
        # This pipe is reachable from receiver
        rtsp_connection, remote.control_connection = multiprocessing.Pipe()
        mainprocess = multiprocessing.Process(target=remote.serve, args=(rtsp_connection,))
        mainprocess.start()

        return remote.port, mainprocess, remote.control_connection
