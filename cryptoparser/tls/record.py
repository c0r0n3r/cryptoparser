#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

import cryptoparser.common.utils as utils

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionFinal, SslVersion
from cryptoparser.tls.subprotocol import TlsSubprotocolMessageBase, TlsSubprotocolMessageParser, TlsContentType, SslMessageBase, SslMessageType, SslSubprotocolMessageParser


class RecordBase(ParsableBase):
    def __init__(self, messages, protocol_version):
        # type: (TlsProtocolVersionBase, TlsSubprotocolMessageBase) -> None
        self.protocol_version = protocol_version
        self.messages = messages

    @property
    def protocol_version(self):
        return self._protocol_version

    @protocol_version.setter
    @abc.abstractmethod
    def protocol_version(self, value):
        raise NotImplementedError()

    @property
    def messages(self):
        return self._messages

    @messages.setter
    @abc.abstractmethod
    def messages(self, value):
        raise NotImplementedError()


class TlsRecord(RecordBase):
    def __init__(self, messages, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2)):
        # type: (TlsProtocolVersionBase, TlsSubprotocolMessageBase) -> None
        super(TlsRecord, self).__init__(messages, protocol_version)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        try:
            parser.parse_numeric('content_type', 1, TlsContentType)
        except InvalidValue as e:
            raise InvalidValue(e.value, TlsContentType)
        parser.parse_parsable('protocol_version', TlsProtocolVersionBase)
        parser.parse_numeric('record_length', 2)
        if parser.unparsed_length < parser['record_length']:
            raise NotEnoughData(parser['record_length'] - parser.unparsed_length)

        parser.parse_variant('messages', TlsSubprotocolMessageParser(parser['content_type']))

        return TlsRecord(messages=[parser['messages'], ], protocol_version=parser['protocol_version']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable(self.messages[0])

        header_composer = ComposerBinary()
        content_type = self.messages[0].get_content_type()
        header_composer.compose_numeric(content_type, 1)
        header_composer.compose_parsable(self.protocol_version)
        header_composer.compose_numeric(body_composer.composed_length, 2)

        return header_composer.composed_bytes + body_composer.composed_bytes

    @RecordBase.protocol_version.setter
    def protocol_version(self, value):
        if not isinstance(value, TlsProtocolVersionBase):
            raise InvalidValue(value, TlsRecord, 'protocol version')

        # pylint: disable=attribute-defined-outside-init
        self._protocol_version = value

    @property
    def content_type(self):
        return self._messages[0].get_content_type()

    @property
    def messages(self):
        return list(self._messages)

    @RecordBase.messages.setter
    def messages(self, value):
        if not all([issubclass(type(item), TlsSubprotocolMessageBase) for item in value]):
            raise ValueError()

        # pylint: disable=attribute-defined-outside-init
        self._messages = value


class SslRecord(RecordBase):
    def __init__(self, message):
        super(SslRecord, self).__init__([message, ], SslVersion.SSL2)

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = ParserBinary(parsable_bytes)

        parser.parse_numeric('record_length_0', 1)
        parser.parse_numeric('record_length_1', 1)
        record_length = ((parser['record_length_0'] & 0x7f) * (2 ** 8)) + parser['record_length_1']
        #FIXME: not enough data
        if parser.parsed_length + record_length > len(parsable_bytes):
            raise NotEnoughData(record_length)

        try:
            parser.parse_numeric('message_type', 1, SslMessageType)
        except InvalidValue as e:
            raise InvalidValue(e.value, SslMessageType)

        parser.parse_variant('message', SslSubprotocolMessageParser(parser['message_type']))

        return SslRecord(message=parser['message']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        message_type = self.messages[0].get_message_type()
        body_composer.compose_numeric(message_type, 1)
        body_composer.compose_parsable(self.messages[0])

        header_composer = ComposerBinary()
        if body_composer.composed_length >= 2 ** 16:
            header_composer.compose_numeric(body_composer.composed_length | (2 ** 23), 2)
        else:
            header_composer.compose_numeric(body_composer.composed_length | (2 ** 15), 2)

        return header_composer.composed_bytes + body_composer.composed_bytes

    @RecordBase.protocol_version.setter
    def protocol_version(self, value):
        if value != SslVersion.SSL2:
            raise InvalidValue(value, SslRecord, 'protocol version')

        # pylint: disable=attribute-defined-outside-init
        self._protocol_version = value

    @RecordBase.messages.setter
    def messages(self, value):
        if not all([issubclass(type(item), SslMessageBase) for item in value]):
            raise ValueError()

        # pylint: disable=attribute-defined-outside-init
        self._messages = value
