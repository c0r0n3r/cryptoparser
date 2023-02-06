# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc

from cryptodatahub.tls.algorithm import TlsCipherSuite, SslCipherKind

from cryptoparser.common.base import TwoByteEnumParsable, ThreeByteEnumParsable


class TlsCipherSuiteFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsCipherSuite

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class SslCipherKindFactory(ThreeByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SslCipherKind

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()
