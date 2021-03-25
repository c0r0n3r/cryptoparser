# -*- coding: utf-8 -*-

import abc
import enum
import functools

import attr

import six

from cryptoparser.common.base import ProtocolVersionBase
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.common.parse import ParserBinary, ComposerBinary


class TlsVersion(enum.IntEnum):
    SSL3 = 0x00
    TLS1_0 = 0x01
    TLS1_1 = 0x02
    TLS1_2 = 0x03
    TLS1_3 = 0x04


@attr.s(order=False, eq=False, hash=True)
@functools.total_ordering
class TlsProtocolVersionBase(ProtocolVersionBase):
    _SIZE = 2

    major = attr.ib()
    minor = attr.ib()

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls._SIZE:
            raise NotEnoughData(bytes_needed=cls._SIZE)

        parser = ParserBinary(parsable)

        parser.parse_numeric('major', 1)
        parser.parse_numeric('minor', 1)

        for subclass in TlsProtocolVersionBase.__subclasses__():
            try:
                version = subclass.__new__(subclass)
                version.major = parser['major']
                version.minor = parser['minor']
                attr.validate(version)
            except InvalidValue:
                pass
            else:
                return version, cls._SIZE

        raise InvalidValue(parsable[:cls._SIZE], cls)

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.major, 1)
        composer.compose_numeric(self.minor, 1)

        return composer.composed_bytes

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.major == other.major and self.minor == other.minor

    def __lt__(self, other):
        if self.major == other.major:
            return self.minor < other.minor
        if isinstance(self, TlsProtocolVersionDraft):
            return other.minor == TlsVersion.TLS1_3

        return self.minor != TlsVersion.TLS1_3

    @property
    @abc.abstractmethod
    def identifier(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __str__(self):
        raise NotImplementedError()


@attr.s(init=False, eq=False, order=False)
class TlsProtocolVersionFinal(TlsProtocolVersionBase):
    _MAJOR = 0x03

    major = attr.ib()
    minor = attr.ib()

    def __init__(self, tls_version):
        self.major = self._MAJOR
        self.minor = tls_version

        attr.validate(self)

    @property
    def identifier(self):
        if self.minor == TlsVersion.SSL3:
            result = 'ssl3'
        elif self.minor == TlsVersion.TLS1_0:
            result = 'tls1'
        else:
            result = 'tls1_{}'.format(self.minor - 1)

        return result

    def __str__(self):
        if self.minor == TlsVersion.SSL3:
            return 'SSL 3.0'

        return 'TLS 1.{}'.format(self.minor - 1)

    @major.validator
    def major_validator(self, attribute, value):  # pylint: disable=unused-argument
        if value != self._MAJOR:
            raise InvalidValue(value, TlsProtocolVersionFinal, 'major')

    @minor.validator
    def minor_validator(self, attribute, value):  # pylint: disable=no-self-use,unused-argument
        try:
            TlsVersion(value)
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], TlsProtocolVersionFinal), e)


@attr.s(init=False, eq=False, order=False)
class TlsProtocolVersionDraft(TlsProtocolVersionBase):
    _MAJOR = 0x7f
    MAX_DRAFT_NUMBER = 28

    major = attr.ib()
    minor = attr.ib()

    def __init__(self, draft_number):
        self.major = self._MAJOR
        self.minor = draft_number

        attr.validate(self)

    @property
    def identifier(self):
        return 'tls1_3_draft{}'.format(self.minor)

    def __str__(self):
        return 'TLS 1.3 Draft {}'.format(self.minor)

    @major.validator
    def major_validator(self, attribute, value):  # pylint: disable=unused-argument
        if value != self._MAJOR:
            raise InvalidValue(value, TlsProtocolVersionFinal, 'major')

    @minor.validator
    def minor_validator(self, attribute, value):  # pylint: disable=unused-argument
        if value > self.MAX_DRAFT_NUMBER:
            raise InvalidValue(value, TlsProtocolVersionDraft, 'draft number')
        if value < 0x00:
            raise InvalidValue(value, TlsProtocolVersionDraft, 'draft number')


class SslVersion(enum.IntEnum):
    SSL2 = 0x0002


@attr.s(eq=True, order=False, hash=True)
@functools.total_ordering
class SslProtocolVersion(ProtocolVersionBase):
    _SIZE = 2

    def __lt__(self, other):
        return isinstance(other, TlsProtocolVersionBase)

    @property
    def identifier(self):
        return 'ssl2'

    def __str__(self):
        return 'SSL 2.0'

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls._SIZE:
            raise NotEnoughData(bytes_needed=cls._SIZE)

        parser = ParserBinary(parsable)

        parser.parse_numeric('version', cls._SIZE, SslVersion)

        return SslProtocolVersion(), cls._SIZE

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(SslVersion.SSL2.value, self._SIZE)

        return composer.composed_bytes
