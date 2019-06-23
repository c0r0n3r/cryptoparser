#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr
import six

from cryptoparser.common.exception import InvalidValue, TooMuchData
from cryptoparser.common.parse import ParsableBase, ParserText, ComposerText

from cryptoparser.ssh.version import SshProtocolVersion


@attr.s
class SshProtocolMessage(ParsableBase):
    protocol_version = attr.ib(validator=attr.validators.instance_of(SshProtocolVersion))
    software_version = attr.ib(validator=attr.validators.instance_of(six.string_types))
    comment = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)), default=None)

    @software_version.validator
    def software_version_validator(self, _, value):  # pylint: disable=no-self-use
        if '\r' in value or '\n' in value or ' ' in value:
            raise InvalidValue(value, SshProtocolMessage, 'software_version')
        try:
            value.encode('ascii')
        except UnicodeEncodeError as e:
            six.raise_from(InvalidValue(value, SshProtocolMessage, 'software_version'), e)

    @comment.validator
    def comment_validator(self, _, value):  # pylint: disable=no-self-use
        if value is not None:
            if '\r' in value or '\n' in value:
                raise InvalidValue(value, SshProtocolMessage, 'comment')
            try:
                value.encode('ascii')
            except UnicodeEncodeError as e:
                six.raise_from(InvalidValue(value, SshProtocolMessage, 'comment'), e)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_by_length('protocol', min_length=3, max_length=3)
        if parser['protocol'] != 'SSH':
            raise InvalidValue(parser['protocol'], SshProtocolMessage, 'protocol')

        parser.parse_string('separator', '-')
        parser.parse_parsable('protocol_version', SshProtocolVersion)
        parser.parse_string('separator', '-')

        parser.parse_string_until_separator('software_version_and_comment', '\n')
        software_version_and_comment = parser['software_version_and_comment'].split(' ')

        if software_version_and_comment[-1][-1] == '\r':
            software_version_and_comment[-1] = software_version_and_comment[-1][:-1]

        software_version = software_version_and_comment[0]
        if len(software_version_and_comment) > 1:
            comment = ' '.join(software_version_and_comment[1:])
        else:
            comment = None
        parser.parse_separator('\n')

        if parser.parsed_length > 255:
            raise TooMuchData(parser.parsed_length - 255)

        return SshProtocolMessage(parser['protocol_version'], software_version, comment), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string('SSH')
        composer.compose_separator('-')
        composer.compose_parsable(self.protocol_version)
        composer.compose_separator('-')
        composer.compose_string(self.software_version)
        if self.comment is not None:
            composer.compose_separator(' ')
            composer.compose_string(self.comment)
        composer.compose_separator('\r\n')

        return composer.composed
