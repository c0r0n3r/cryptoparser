#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum

import six

from cryptoparser.common.base import JSONSerializable
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary


class TlsVersion(enum.IntEnum):
    SSL3 = 0x00
    TLS1_0 = 0x01
    TLS1_1 = 0x02
    TLS1_2 = 0x03
    TLS1_3 = 0x04


@six.add_metaclass(abc.ABCMeta)
class TlsProtocolVersionBase(JSONSerializable, ParsableBase):
    _SIZE = 2

    def __init__(self, major, minor):
        self._major = None
        self._minor = None

        self.major = major
        self.minor = minor

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

        return isinstance(self, TlsProtocolVersionDraft) == (other.minor == TlsVersion.TLS1_3)

    def __hash__(self):
        return hash(str(self))

    def as_json(self):
        return repr(self)

    @abc.abstractmethod
    def __str__(self):
        raise NotImplementedError()

    @property
    def major(self):
        return self._major

    @major.setter
    @abc.abstractproperty
    def major(self, value):
        raise NotImplementedError()

    @property
    def minor(self):
        return self._minor

    @minor.setter
    @abc.abstractmethod
    def minor(self, value):
        raise NotImplementedError()


class TlsProtocolVersionFinal(TlsProtocolVersionBase):
    _MAJOR = 0x03

    def __init__(self, tls_version):
        # type: (TlsVersion) -> None
        super(TlsProtocolVersionFinal, self).__init__(self._MAJOR, tls_version)

    def __repr__(self):
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

    # pylint: disable=no-member
    @TlsProtocolVersionBase.major.setter
    def major(self, value):
        # type: (int) -> None
        if value != self._MAJOR:
            raise InvalidValue(value, TlsProtocolVersionFinal, 'major')

        self._major = value

    @TlsProtocolVersionBase.minor.setter
    def minor(self, value):
        # type: (TlsVersion) -> None
        try:
            TlsVersion(value)
        except ValueError as e:
            raise InvalidValue(e.args[0], TlsProtocolVersionFinal)

        self._minor = value


class TlsProtocolVersionDraft(TlsProtocolVersionBase):
    _MAJOR = 0x7f
    MAX_DRAFT_NUMBER = 0xff

    def __init__(self, draft_number):
        # type: (int) -> None
        super(TlsProtocolVersionDraft, self).__init__(self._MAJOR, draft_number)

    def __repr__(self):
        return 'tls1_3_draft{}'.format(self.minor - 1)

    def __str__(self):
        return 'TLS 1.3 Draft {}'.format(self.minor - 1)

    # pylint: disable=no-member
    @TlsProtocolVersionBase.major.setter
    def major(self, value):
        # type: (int) -> None
        if value != self._MAJOR:
            raise InvalidValue(value, TlsProtocolVersionFinal, 'major')

        self._major = value

    @TlsProtocolVersionBase.minor.setter
    def minor(self, value):
        # type: (int) -> None
        if value > 0xff:
            raise InvalidValue(value, TlsProtocolVersionDraft, 'draft number')
        if value < 0x00:
            raise InvalidValue(value, TlsProtocolVersionDraft, 'draft number')

        self._minor = value


class TlsVersionGrease(enum.IntEnum):
    GREASE_0A0A = 0x0A0A
    GREASE_1A1A = 0x1A1A
    GREASE_2A2A = 0x2A2A
    GREASE_3A3A = 0x3A3A
    GREASE_4A4A = 0x4A4A
    GREASE_5A5A = 0x5A5A
    GREASE_6A6A = 0x6A6A
    GREASE_7A7A = 0x7A7A
    GREASE_8A8A = 0x8A8A
    GREASE_9A9A = 0x9A9A
    GREASE_AAAA = 0xAAAA
    GREASE_BABA = 0xBABA
    GREASE_CACA = 0xCACA
    GREASE_DADA = 0xDADA
    GREASE_EAEA = 0xEAEA
    GREASE_FAFA = 0xFAFA


class TlsProtocolVersionGrease(TlsProtocolVersionBase):
    def __init__(self, grease):
        major = grease.value >> 8
        minor = grease.value & 0x00ff

        super(TlsProtocolVersionGrease, self).__init__(major, minor)


class SslVersion(enum.IntEnum):
    SSL2 = 0x0002


@six.add_metaclass(abc.ABCMeta)
class SslProtocolVersion(JSONSerializable, ParsableBase):
    _SIZE = 2

    def __eq__(self, other):
        return isinstance(other, SslProtocolVersion)

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
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
