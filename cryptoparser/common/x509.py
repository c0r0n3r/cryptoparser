# -*- coding: utf-8 -*-

from cryptoparser.common.base import (
    Opaque,
    OpaqueParam,
    VectorParamParsable,
    VectorParsable,
)


class SerializedSCT(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
        )


class SignedCertificateTimestampList(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=SerializedSCT,
            fallback_class=None,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )
