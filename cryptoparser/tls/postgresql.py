# -*- coding: utf-8 -*-

import attr

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidValue


@attr.s
class Sync(ParsableBase):
    MESSAGE_SIZE = 1
    COMMAND = b'S'

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_raw('command', cls.MESSAGE_SIZE)
        if parser['command'] != cls.COMMAND:
            raise InvalidValue(parser['command'], cls, 'command')

        return cls(), cls.MESSAGE_SIZE

    def compose(self):
        composer = ComposerBinary()

        composer.compose_raw(self.COMMAND)

        return composer.composed_bytes


class SslRequest(ParsableBase):
    MESSAGE_SIZE = 8
    REQUEST_CODE = 80877103

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.MESSAGE_SIZE:
            raise NotEnoughData(cls.MESSAGE_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('length', 4)
        if parser['length'] != cls.MESSAGE_SIZE:
            raise InvalidValue(parser['length'], cls, 'length')

        parser.parse_numeric('request_code', 4)
        if parser['request_code'] != cls.REQUEST_CODE:
            raise InvalidValue(parser['request_code'], cls, 'request_code')

        return cls(), cls.MESSAGE_SIZE

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.MESSAGE_SIZE, 4)
        composer.compose_numeric(self.REQUEST_CODE, 4)

        return composer.composed_bytes
