# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import collections
import datetime
import enum
import hashlib

import attr

import asn1crypto

from cryptodatahub.common.key import PublicKeyX509Base
from cryptodatahub.common.stores import CertificateTransparencyLog, CertificateTransparencyLogParamsBase

from cryptoparser.common.base import (
    Opaque,
    OpaqueParam,
    Serializable,
    VectorParamParsable,
    VectorParsable,
)
from cryptoparser.common.parse import ComposerBinary, ComposerText, ParsableBase, ParserBinary

from cryptoparser.tls.algorithm import TlsSignatureAndHashAlgorithm, TlsSignatureAndHashAlgorithmFactory


class CtExtensions(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=0,
            max_byte_num=2 ** 16 - 1,
        )


class CtSignature(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=0,
            max_byte_num=2 ** 16 - 1,
        )


class CtVersion(enum.IntEnum):
    V1 = 0x00  # pylint: disable=invalid-name


@attr.s
class SignedCertificateTimestamp(ParsableBase, Serializable):
    version = attr.ib(validator=attr.validators.in_(CtVersion))
    log = attr.ib(
        converter=CertificateTransparencyLog.from_log_id,
        validator=attr.validators.instance_of(CertificateTransparencyLogParamsBase)
    )
    timestamp = attr.ib(validator=attr.validators.instance_of(datetime.datetime))
    extensions = attr.ib(
        validator=attr.validators.instance_of(CtExtensions)
    )
    signature_algorithm = attr.ib(validator=attr.validators.in_(TlsSignatureAndHashAlgorithm))
    signature = attr.ib(
        converter=CtSignature,
        validator=attr.validators.instance_of(CtSignature),
        metadata={'human_friendly': False},
    )

    @classmethod
    def _parse(cls, parsable):
        header_parser = ParserBinary(parsable)
        header_parser.parse_bytes('sct', 2)

        body_parser = ParserBinary(header_parser['sct'])

        body_parser.parse_numeric('version', 1, CtVersion)
        body_parser.parse_raw('log', 32)
        body_parser.parse_timestamp('timestamp', milliseconds=True)
        body_parser.parse_parsable('extensions', CtExtensions)
        body_parser.parse_parsable('signature_algorithm', TlsSignatureAndHashAlgorithmFactory)
        body_parser.parse_parsable('signature', CtSignature)

        return cls(**body_parser), header_parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()

        body_composer.compose_numeric(self.version, 1)
        body_composer.compose_raw(self.log.log_id.value)
        body_composer.compose_timestamp(self.timestamp, milliseconds=True)
        body_composer.compose_parsable(self.extensions)
        body_composer.compose_numeric_enum_coded(self.signature_algorithm)
        body_composer.compose_parsable(self.signature)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(len(body_composer.composed_bytes), 2)

        return header_composer.composed_bytes + body_composer.composed_bytes


class SignedCertificateTimestampList(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=SignedCertificateTimestamp,
            fallback_class=None,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


@attr.s(frozen=True)
class TlsJA4XFingerprint(Serializable):
    fingerprint = attr.ib(validator=attr.validators.instance_of(str))
    fingerprint_raw = attr.ib(validator=attr.validators.instance_of(str))


@attr.s(eq=False, init=False, frozen=True)
class PublicKeyX509(PublicKeyX509Base):
    ja4x = attr.ib(init=False, default=None, metadata={'human_readable_name': 'JA4X'})

    def __init__(self, certificate):
        super().__init__(certificate)

        object.__setattr__(self, 'ja4x', self._ja4x())

    @property
    def signed_certificate_timestamps(self):
        for extension in self._certificate['tbs_certificate']['extensions']:
            if extension['extn_id'].dotted == '1.3.6.1.4.1.11129.2.4.2':
                asn1_value = asn1crypto.core.load(bytes(extension['extn_value']))
                return SignedCertificateTimestampList.parse_exact_size(bytes(asn1_value))

        return SignedCertificateTimestampList([])

    @staticmethod
    def _ja4x_sha256(oid_hexes):
        composer = ComposerText()
        composer.compose_string_array(oid_hexes, ',')
        return hashlib.sha256(composer.composed).hexdigest()[:12]

    @staticmethod
    def _ja4x_relative_distinguished_name_oid_hexes(name):
        return [
            attribute['type'].contents.hex()
            for relative_distinguished_name in name.chosen
            for attribute in relative_distinguished_name
        ]

    def _ja4x(self):
        tbs_certificate = self._certificate['tbs_certificate']
        issuer_oid_hexes = self._ja4x_relative_distinguished_name_oid_hexes(tbs_certificate['issuer'])
        subject_oid_hexes = self._ja4x_relative_distinguished_name_oid_hexes(tbs_certificate['subject'])
        extension_oid_hexes = [
            extension['extn_id'].contents.hex()
            for extension in tbs_certificate['extensions']
        ]

        fingerprint_composer = ComposerText()
        fingerprint_composer.compose_string_array([
            self._ja4x_sha256(issuer_oid_hexes),
            self._ja4x_sha256(subject_oid_hexes),
            self._ja4x_sha256(extension_oid_hexes),
        ], '_')

        raw_composer = ComposerText()
        raw_composer.compose_string_array(issuer_oid_hexes, ',')
        for oid_hexes in (subject_oid_hexes, extension_oid_hexes):
            raw_composer.compose_separator('_')
            raw_composer.compose_string_array(oid_hexes, ',')

        return TlsJA4XFingerprint(
            fingerprint=fingerprint_composer.composed.decode('ascii'),
            fingerprint_raw=raw_composer.composed.decode('ascii'),
        )

    def _asdict(self):
        dict_value = super()._asdict()

        return collections.OrderedDict(list(dict_value.items()) + [
            ('ja4x', self.ja4x),
            ('signed_certificate_timestamps', self.signed_certificate_timestamps),
        ])
