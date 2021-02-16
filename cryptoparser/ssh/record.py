#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.subprotocol import SshHandshakeMessageVariant, SshMessageBase


@attr.s
class SshRecord(ParsableBase):
    packet = attr.ib(validator=attr.validators.instance_of(SshMessageBase))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('packet_length', 4)
        if parser['packet_length'] > parser.unparsed_length:
            raise NotEnoughData(parser['packet_length'] - parser.unparsed_length)
        parser.parse_numeric('padding_length', 1)

        parser.parse_parsable('packet', SshHandshakeMessageVariant)

        parser.parse_raw('padding', parser['padding_length'])

        return SshRecord(packet=parser['packet']), parser.parsed_length

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
