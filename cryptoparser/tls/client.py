#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.exception import NotEnoughData, NetworkError, NetworkErrorType
from cryptoparser.common.utils import get_leaf_classes

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.subprotocol import SslMessageBase, SslMessageType, SslHandshakeClientHello
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsAlertDescription, TlsCipherSuiteVector, TlsContentType, TlsHandshakeType
from cryptoparser.tls.extension import TlsExtensionSupportedVersions, TlsExtensionServerName
from cryptoparser.tls.extension import TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithm
from cryptoparser.tls.extension import TlsExtensionECPointFormats, TlsECPointFormat
from cryptoparser.tls.extension import TlsExtensionEllipticCurves, TlsNamedCurve

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslVersion

import imaplib
import poplib
import smtplib

import socket


class TlsHandshakeClientHelloAnyAlgorithm(TlsHandshakeClientHello):
    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAnyAlgorithm, self).__init__(
            cipher_suites=TlsCipherSuiteVector(list(TlsCipherSuite)),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloAuthenticationRSA(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.authentication and
            cipher_suite.value.authentication in [Authentication.RSA, Authentication.RSA_EXPORT])
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAuthenticationRSA, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloAuthenticationDSS(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.authentication and
            cipher_suite.value.authentication in [Authentication.DSS, Authentication.DSS_EXPORT])
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAuthenticationDSS, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
            ]
        )


class TlsHandshakeClientHelloAuthenticationECDSA(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.authentication and
            cipher_suite.value.authentication in [Authentication.ECDSA, ])
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAuthenticationECDSA, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloKeyExchangeECDHx(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.key_exchange and
            cipher_suite.value.key_exchange in [KeyExchange.ECDH, KeyExchange.ECDHE])
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloKeyExchangeECDHx, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloBasic(TlsHandshakeClientHello):
    def __init__(self):
        super(TlsHandshakeClientHelloBasic, self).__init__(
            cipher_suites=TlsCipherSuiteVector(list(TlsCipherSuite)),
            extensions=[]
        )


class L7Client(object):
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._socket = None
        self._buffer = bytearray()

    def do_ssl_handshake(self, hello_message, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        self._socket = self._connect()
        tls_client = SslClientHandshake(self)
        server_messages = tls_client.do_handshake(hello_message, SslVersion.SSL2, last_handshake_message_type)
        self._close()

        return server_messages

    def do_tls_handshake(self, hello_message=None, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE):
        self._socket = self._connect()
        tls_client = TlsClientHandshake(self)
        server_messages = tls_client.do_handshake(hello_message, protocol_version, last_handshake_message_type)
        self._close()

        return server_messages

    def _close(self):
        self._socket.close()
        self._socket = None

    def send(self, sendable_bytes):
        total_sent_byte_num = 0
        while total_sent_byte_num < len(sendable_bytes):
            actual_sent_byte_num = self._socket.send(sendable_bytes[total_sent_byte_num:])
            if actual_sent_byte_num == 0:
                raise IOError()
            total_sent_byte_num = total_sent_byte_num + actual_sent_byte_num

    def receive(self, receivable_byte_num):
        total_received_byte_num = 0
        while total_received_byte_num < receivable_byte_num:
            try:
                actual_received_bytes = self._socket.recv(min(receivable_byte_num - total_received_byte_num, 1024))
                self._buffer += actual_received_bytes
                total_received_byte_num += len(actual_received_bytes)
            except socket.error as e:
                actual_received_bytes = None

            if not actual_received_bytes:
                raise NotEnoughData(receivable_byte_num - total_received_byte_num)

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def buffer(self):
        return bytearray(self._buffer)

    def flush_buffer(self, byte_num=None):
        if byte_num is None:
            byte_num = len(self._buffer)

        self._buffer = self._buffer[byte_num:]

    @classmethod
    def from_scheme(cls, scheme, host, port=None):
        for client_class in get_leaf_classes(L7Client):
            if client_class.get_scheme() == scheme:
                port = client_class.get_default_port() if port is None else port
                return client_class(host, port)
        else:
            raise ValueError()

    @classmethod
    def get_supported_schemes(cls):
        return set([leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(cls)])

    @abc.abstractmethod
    def _connect(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()


class L7ClientTls(L7Client):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 443

    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._host, self._port))
        return sock


class L7ClientHTTPS(L7Client):
    @classmethod
    def get_scheme(cls):
        return 'https'

    @classmethod
    def get_default_port(cls):
        return 443

    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._host, self._port))
        return sock


class ClientPOP3(L7Client):
    def __init__(self, host, port):
        super(ClientPOP3, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'pop'

    @classmethod
    def get_default_port(cls):
        return 110

    def _connect(self):
        #FIXME: self
        self.client = poplib.POP3(self._host, self._port)
        if 'STLS' not in self.capa():
            raise ValueError
        response = self.stls()
        if response != b'+OK':
            raise ValueError
        return self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()


class ClientSMTP(L7Client):
    def __init__(self, host, port):
        super(ClientSMTP, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 587

    def _connect(self):
        #FIXME: self
        self.client = smtplib.SMTP()
        self.client.connect(self._host, self._port)
        self.client.ehlo()
        if not self.client.has_extn('STARTTLS'):
            raise ValueError
        response, message = self.client.docmd('STARTTLS')
        if response != 220:
            raise ValueError
        return self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()


class ClientIMAP(L7Client):
    def __init__(self, host, port):
        super(ClientIMAP, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'imap'

    @classmethod
    def get_default_port(cls):
        return 143

    def _connect(self):
        #FIXME: self
        self.client = imaplib.IMAP4(self._host, self._port)
        if 'STARTTLS' not in self.client.capabilities:
            raise ValueError
        response, message = self.client.xatom('STARTTLS')
        if response != 'OK':
            raise ValueError
        return self.client.socket()

    def close(self):
        if self._socket:
            self.client.quit()


class InvalidState(ValueError):
    def __init__(self, description):
        super(InvalidState, self).__init__()

        self.description = description


class TlsAlert(ValueError):
    def __init__(self, description):
        super(TlsAlert, self).__init__()

        self.description = description


class TlsClient(object):
    def __init__(self, l4_client):
        self._l4_client = l4_client

    @abc.abstractmethod
    def do_handshake(self, hello_message, protocol_version, last_handshake_message_type):
        raise NotImplementedError()


class TlsClientHandshake(TlsClient):
    def do_handshake(
        self,
        hello_message=None,
        protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0),
        last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        if hello_message is None:
            hello_message = TlsHandshakeClientHelloAnyAlgorithm(self._host)

        tls_record = TlsRecord([hello_message, ], protocol_version)
        self._l4_client.send(tls_record.compose())

        server_messages = {}
        while True:
            try:
                record = TlsRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
                if record.content_type == TlsContentType.ALERT:
                    raise TlsAlert(record.messages[0].description)
                elif record.content_type != TlsContentType.HANDSHAKE:
                    raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                for handshake_message in record.messages:
                    if handshake_message.get_handshake_type() in server_messages:
                        raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                    handshake_type = handshake_message.get_handshake_type()
                    server_messages[handshake_type] = handshake_message
                    if handshake_type == last_handshake_message_type:
                        return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)


class SslError(ValueError):
    def __init__(self, error):
        super(SslError, self).__init__()

        self.error = error


class SslHandshakeClientHelloAnyAlgorithm(SslHandshakeClientHello):
    def __init__(self):
        super(SslHandshakeClientHelloAnyAlgorithm, self).__init__(cipher_kinds=list(SslCipherKind))


class SslClientHandshake(TlsClient):
    def do_handshake(self, hello_message=None, protocol_version=SslVersion.SSL2, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        if hello_message is None:
            hello_message = SslHandshakeClientHelloAnyAlgorithm(self._host)

        ssl_record = SslRecord(hello_message)
        self._l4_client.send(ssl_record.compose())

        server_messages = {}
        while True:
            try:
                record = SslRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
                message = record.messages[0]
                #FIXME: error message is not parsed
                if message.get_message_type() == SslMessageType.ERROR:
                    raise SslError(message.get_message_type())

                server_messages[message.get_message_type()] = message
                if message.get_message_type() == last_handshake_message_type:
                    return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    try:
                        print(self._l4_client.buffer)
                        tls_record = TlsRecord.parse_exact_size(self._l4_client.buffer)
                        self._l4_client.flush_buffer()
                    except ValueError as e:
                        raise NetworkError(NetworkErrorType.NO_CONNECTION)
                    else:
                        print( tls_record.messages[0].description)
                        if (tls_record.content_type == TlsContentType.ALERT and
                            tls_record.messages[0].description in [
                                TlsAlertDescription.PROTOCOL_VERSION,
                                TlsAlertDescription.INTERNAL_ERROR,
                            ]
                        ):
                            raise NetworkError(NetworkErrorType.NO_RESPONSE)
                        else:
                            raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
