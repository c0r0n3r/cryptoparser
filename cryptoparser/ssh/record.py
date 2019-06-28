#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

import attr

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.subprotocol import (
    SshMessageBase,
    SshMessageVariantInit,
    SshMessageVariantKexDH,
    SshMessageVariantKexDHGroup,
)


@attr.s
class SshRecordBase(ParsableBase):
    HEADER_SIZE = 6

    packet = attr.ib(validator=attr.validators.instance_of(SshMessageBase))

    @classmethod
    @abc.abstractmethod
    def _get_variant_class(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('packet_length', 4)
        if parser['packet_length'] > parser.unparsed_length:
            raise NotEnoughData(parser['packet_length'] - parser.unparsed_length)
        parser.parse_numeric('padding_length', 1)

        parser.parse_parsable('packet', cls._get_variant_class())

        parser.parse_raw('padding', parser['padding_length'])

        return cls(packet=parser['packet']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable(self.packet)

        payload_length = body_composer.composed_length
        padding_length = 8 - ((payload_length + 5) % 8)
        if padding_length < 4:
            padding_length += 8
        packet_length = payload_length + padding_length + 1
        for _ in range(padding_length):
            body_composer.compose_numeric(0, 1)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(packet_length, 4)
        header_composer.compose_numeric(padding_length, 1)

        return header_composer.composed + body_composer.composed


class SshRecordInit(SshRecordBase):
    @classmethod
    def _get_variant_class(cls):
        return SshMessageVariantInit


class SshRecordKexDH(SshRecordBase):
    @classmethod
    def _get_variant_class(cls):
        return SshMessageVariantKexDH


class SshRecordKexDHGroup(SshRecordBase):
    @classmethod
    def _get_variant_class(cls):
        return SshMessageVariantKexDHGroup
