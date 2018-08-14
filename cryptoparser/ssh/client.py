#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.backends import cryptography_default_backend
from cryptography.hazmat.primitives.asymmetric import cryptography_ec, cryptography_dh
from cryptoparser.ssh.subprotocol import SshECDHKeyExchangeInit

from cryptoparser.common.client import L7ClientTcp
from cryptoparser.common.exception import NotEnoughData, NetworkError, NetworkErrorType
from cryptoparser.common.parse import ParserText

from cryptoparser.ssh.record import SshRecord
from cryptoparser.ssh.subprotocol import SshMessageCode, SshProtocolMessage, SshKeyExchangeInit
from cryptoparser.ssh.subprotocol import SshKexAlgorithms, SshEncryptionAlgorithms, SshMacAlgorithms
from cryptoparser.ssh.subprotocol import SshCompressionAlgorithms
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion


class SshKeyExchangeInitAnyAlgorithm(SshKeyExchangeInit):
    def __init__(self):
        super(SshKeyExchangeInitAnyAlgorithm, self).__init__(
            kex_algorithms=list(SshKexAlgorithms),
            server_host_key_algorithms=list(SshKexAlgorithms),
            encryption_algorithms_client_to_server=list(SshEncryptionAlgorithms),
            encryption_algorithms_server_to_client=list(SshEncryptionAlgorithms),
            mac_algorithms_client_to_server=list(SshMacAlgorithms),
            mac_algorithms_server_to_client=list(SshMacAlgorithms),
            compression_algorithms_client_to_server=list(SshCompressionAlgorithms),
            compression_algorithms_server_to_client=list(SshCompressionAlgorithms),
        )


class ClientSsh(L7ClientTcp):
    @classmethod
    def get_scheme(cls):
        return 'ssh'

    @classmethod
    def get_default_port(cls):
        return 22

    def do_handshake(
            self,
            protocol_message=SshProtocolMessage(
                protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
                product='Cryptolyter_0.1',
                comment='https://github.com/c0r0n3r/cyrptolyze'
            ),
            key_exchange_init_message=SshKeyExchangeInitAnyAlgorithm(),
            last_message_type=SshKeyExchangeInit
    ):
        self._socket = self._connect()
        tls_client = SshClientHandshake(self)
        server_messages = tls_client.do_handshake(
            protocol_message,
            key_exchange_init_message,
            last_message_type
        )
        self._close()

        return server_messages


L7ClientTcp.register(ClientSsh)


def get_ecdh_public_key():
    # Generate a private key for use in the exchange.
    private_key = cryptography_ec.generate_private_key(
        cryptography_ec.SECP521R1(), cryptography_default_backend()
    )
    return private_key.public_key()


def get_dh_public_key():
    parameters = cryptography_dh.generate_parameters(
        generator=2, key_size=1024, backend=cryptography_default_backend()
    )
    # Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()
    return private_key.public_key()


class SshDisconnect(ValueError):
    def __init__(self, reason):
        super(SshDisconnect, self).__init__()

        self.reason = reason


class SshClientHandshake(object):
    def __init__(self, l4_client):
        self._l4_client = l4_client

    def exchange_version(self, protocol_message):
        self._l4_client.send(protocol_message.compose())

        parsable_bytes = self._l4_client.receive_at_most(256)
        parser = ParserText(parsable_bytes)
        parser.parse_parsable('protocol_message', SshProtocolMessage)

        return parser

    def do_handshake(
            self,
            protocol_message,
            key_exchange_init_message,
            last_message_type
    ):
        parser = self.exchange_version(protocol_message)
        server_messages = {SshProtocolMessage: parser['protocol_message']}
        if last_message_type == SshProtocolMessage:
            return server_messages

        self._l4_client.send(SshRecord(key_exchange_init_message).compose())
        self._l4_client.send(SshRecord(SshECDHKeyExchangeInit(get_ecdh_public_key())).compose())

        received_bytes = protocol_message[-parser.unparsed_length:]
        while True:
            try:
                record = SshRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
                if record.packet.get_message_code() == SshMessageCode.DISCONNECT:
                    raise SshDisconnect(record.packet.reason)

                server_messages[type(record.packet)] = record.packet
                if isinstance(record.packet, last_message_type):
                    return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if received_bytes:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
