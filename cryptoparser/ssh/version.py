#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum
import six

import attr

from cryptoparser.common.base import ProtocolVersionBase
from cryptoparser.common.exception import InvalidValue
from cryptoparser.common.parse import ParserText, ComposerText


class SshVersion(enum.IntEnum):
    SSH1 = 1
    SSH2 = 2


@attr.s(hash=True)
class SshProtocolVersion(ProtocolVersionBase):
    major = attr.ib(converter=SshVersion, validator=attr.validators.instance_of(SshVersion))
    minor = attr.ib(validator=attr.validators.instance_of(int), default=0)

    def __str__(self):
        return 'SSH {}.{}'.format(self.major, self.minor)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_numeric('major')
            parser.parse_separator('.')
            parser.parse_numeric('minor')
        except InvalidValue as e:
            six.raise_from(InvalidValue(parsable, SshProtocolVersion), e)

        return SshProtocolVersion(parser['major'], parser['minor']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_numeric(self.major.value)
        composer.compose_separator('.')
        composer.compose_numeric(self.minor)

        return composer.composed

    @property
    def identifier(self):
        return 'ssh{}'.format(self.major)

    @property
    def supported_versions(self):
        if self.major == SshVersion.SSH1 and self.minor == 99:
            return [SshVersion.SSH1, SshVersion.SSH2]

        return [self.major, ]
