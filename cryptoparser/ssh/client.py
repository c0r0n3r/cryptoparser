#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

from cryptoparser.common.client import L7ClientTcp
from cryptoparser.common.exception import NotEnoughData, NetworkError, NetworkErrorType
from cryptoparser.common.parse import ParserBinary, ParserText

from cryptoparser.ssh.record import SshRecord
from cryptoparser.ssh.subprotocol import SshProtocolMessage, SshKeyExchangeInit
from cryptoparser.ssh.subprotocol import SshKexAlogrithms, SshEncryptionAlogrithms, SshHostKeyAlogrithms, SshCompressionAlogrithms
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion


class SshKeyExchangeInitAnyAlgorithm(SshKeyExchangeInit):
    def __init__(self):
        super(SshKeyExchangeInitAnyAlgorithm, self).__init__(
            kex_algorithms=list(SshKexAlogrithms),
            server_host_key_algorithms=list(SshKexAlogrithms),
            encryption_algorithms_client_to_server=list(SshEncryptionAlogrithms),
            encryption_algorithms_server_to_client=list(SshEncryptionAlogrithms),
            mac_algorithms_client_to_server=list(SshHostKeyAlogrithms),
            mac_algorithms_server_to_client=list(SshHostKeyAlogrithms),
            compression_algorithms_client_to_server=list(SshCompressionAlogrithms),
            compression_algorithms_server_to_client=list(SshCompressionAlogrithms),
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


class SshClientHandshake(object):
    def __init__(self, l4_client):
        self._l4_client = l4_client

    def exchange_version(self, protocol_message):
        self._l4_client.send(
            SshProtocolMessage(
                protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
                product='Cryptolyter_0.1',
                comment='https://github.com/c0r0n3r/cyrptolyze').compose()
        )

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

        self._l4_client.send(key_exchange_init_message.compose())

        received_bytes = parser._parsable[parser._parsed_length:]
        while True:
            try:
                parser = ParserBinary(received_bytes)
                parser.parse_parsable('record', SshRecord)
                record = parser['record']

                server_messages[type(record.packet)] = record.packet
                if type(record.packet) == last_message_type:
                    return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            try:
                actual_received_bytes = self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if received_bytes:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
            received_bytes += actual_received_bytes
