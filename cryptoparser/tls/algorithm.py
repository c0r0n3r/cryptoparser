# -*- coding: utf-8 -*-

import abc

from cryptodatahub.tls.algorithm import TlsECPointFormat, TlsNamedCurve, TlsSignatureAndHashAlgorithm

from cryptoparser.common.base import OneByteEnumParsable, TwoByteEnumParsable


class TlsNamedCurveFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsNamedCurve

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsSignatureAndHashAlgorithmFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsSignatureAndHashAlgorithm

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsECPointFormatFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsECPointFormat

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()
