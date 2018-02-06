#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cryptoparser.common.utils as utils

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionFinal
from cryptoparser.tls.subprotocol import TlsSubprotocolMessageBase, TlsContentType


class TlsRecord(ParsableBase):
    def __init__(self, messages, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2)):
        self.protocol_version = protocol_version
        self.messages = messages

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

        header_size = parser.parsed_length

        messages = []
        while parser.parsed_length < parser['record_length'] + header_size:
            for subclass in utils.get_leaf_classes(TlsSubprotocolMessageBase):
                if subclass.get_content_type() != parser['content_type']:
                    continue

                try:
                    parser.parse_parsable('message', subclass)
                    messages.append(parser['message'])
                    break
                except InvalidValue:
                    continue
            else:
                raise InvalidValue(parser['content_type'], TlsRecord, 'content type')

        return TlsRecord(messages=messages, protocol_version=parser['protocol_version']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable(self.messages[0])

        header_composer = ComposerBinary()
        content_type = self.messages[0].get_content_type()
        header_composer.compose_numeric(content_type, 1)
        header_composer.compose_parsable(self.protocol_version)
        header_composer.compose_numeric(body_composer.composed_length, 2)

        return header_composer.composed_bytes + body_composer.composed_bytes

    @property
    def protocol_version(self):
        return self._protocol_version

    @protocol_version.setter
    def protocol_version(self, value):
        if not isinstance(value, TlsProtocolVersionBase):
            raise ValueError()

        # pylint: disable=attribute-defined-outside-init
        self._protocol_version = value

    @property
    def messages(self):
        return self._messages

    @messages.setter
    def messages(self, value):
        if not all([issubclass(type(item), TlsSubprotocolMessageBase) for item in value]):
            raise ValueError()

        # pylint: disable=attribute-defined-outside-init
        self._messages = value
