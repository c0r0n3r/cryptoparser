#!/usr/bin/env python
# -*- coding: utf-8 -*-


from cryptoparser.common.exception import InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserText, ComposerText


class LanguageTag(ParsableBase):
    def __init__(self, primary_subtag, subsequent_subtags=()):
        self._primary_subtag = None
        self._subsequent_subtags = None

        self.primary_subtag = primary_subtag
        self.subsequent_subtags = subsequent_subtags

    @property
    def primary_subtag(self):
        return self._primary_subtag

    @primary_subtag.setter
    def primary_subtag(self, value):
        if not value or len(value) > 8 or not value.isalpha():
            raise InvalidValue(value, LanguageTag, 'primary_subtag')

        self._primary_subtag = value

    @property
    def subsequent_subtags(self):
        return self._subsequent_subtags

    @subsequent_subtags.setter
    def subsequent_subtags(self, value):
        for subsequent_subtag in value:
            if not subsequent_subtag or len(subsequent_subtag) > 8 or not subsequent_subtag.isalnum():
                raise InvalidValue(value, LanguageTag, 'subsequent_subtag')

        self._subsequent_subtags = value

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)
        parser.parse_string_array('tags', '-')

        return LanguageTag(parser['tags'][0], parser['tags'][1:]), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.primary_subtag)
        if self.subsequent_subtags:
            composer.compose_separator('-')
            composer.compose_string_array(self.subsequent_subtags, '-')

        return composer.composed
