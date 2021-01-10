# -*- coding: utf-8 -*-

import attr

import six

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionFinal, SslVersion
from cryptoparser.tls.subprotocol import TlsSubprotocolMessageBase, TlsSubprotocolMessageParser, TlsContentType
from cryptoparser.tls.subprotocol import SslMessageBase, SslMessageType, SslSubprotocolMessageParser


@attr.s
class TlsRecord(ParsableBase):
    HEADER_SIZE = 5

    messages = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(TlsSubprotocolMessageBase))
    )
    protocol_version = attr.ib(
        default=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        validator=attr.validators.instance_of(TlsProtocolVersionBase),
    )

    @classmethod
    def parse_header(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        try:
            parser.parse_numeric('content_type', 1, TlsContentType)
        except InvalidValue as e:
            six.raise_from(InvalidValue(e.value, TlsContentType), e)
        parser.parse_parsable('protocol_version', TlsProtocolVersionBase)
        parser.parse_numeric('record_length', 2)

        return parser

    @classmethod
    def _parse(cls, parsable):
        parser = cls.parse_header(parsable)

        if parser.unparsed_length < parser['record_length']:
            raise NotEnoughData(parser['record_length'] - parser.unparsed_length)

        messages = []
        while parser.parsed_length < cls.HEADER_SIZE + parser['record_length']:
            parser.parse_variant('message', TlsSubprotocolMessageParser(parser['content_type']))
            messages.append(parser['message'])

        return TlsRecord(
            messages=messages,
            protocol_version=parser['protocol_version']
        ), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        for message in self.messages:
            body_composer.compose_parsable(message)

        header_composer = ComposerBinary()
        content_type = self.messages[0].get_content_type()
        header_composer.compose_numeric(content_type, 1)
        header_composer.compose_parsable(self.protocol_version)
        header_composer.compose_numeric(body_composer.composed_length, 2)

        return header_composer.composed_bytes + body_composer.composed_bytes

    @property
    def content_type(self):
        return self.messages[0].get_content_type()


@attr.s
class SslRecord(ParsableBase):
    message = attr.ib(validator=attr.validators.instance_of(SslMessageBase))
    protocol_version = attr.ib(init=False, default=SslVersion.SSL2, validator=attr.validators.in_(SslVersion))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('record_length_0', 1)
        parser.parse_numeric('record_length_1', 1)
        if parser['record_length_0'] & 0x80:
            record_length = ((parser['record_length_0'] & 0x7f) * (2 ** 8)) + parser['record_length_1']
            padding_length = 0
        else:
            record_length = ((parser['record_length_0'] & 0x3f) * (2 ** 8)) + parser['record_length_1']
            parser.parse_numeric('padding_length', 1)
            padding_length = parser['padding_length']

        if record_length > parser.unparsed_length:
            raise NotEnoughData(record_length - parser.unparsed_length)

        try:
            parser.parse_numeric('message_type', 1, SslMessageType)
        except InvalidValue as e:
            six.raise_from(InvalidValue(e.value, SslMessageType), e)

        parser.parse_variant('message', SslSubprotocolMessageParser(parser['message_type']))
        parser.parse_bytes('padding', padding_length)

        return SslRecord(message=parser['message']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        message_type = self.message.get_message_type()
        body_composer.compose_numeric(message_type, 1)
        body_composer.compose_parsable(self.message)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length | (2 ** 15), 2)

        return header_composer.composed_bytes + body_composer.composed_bytes

    @property
    def content_type(self):
        return self.message.get_message_type()
