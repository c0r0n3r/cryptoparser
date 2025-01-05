# -*- coding: utf-8 -*-

import enum

import attr

from cryptoparser.common.base import Serializable


@attr.s(frozen=True)
class HttpVersionParams(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(str))
    name = attr.ib(validator=attr.validators.instance_of(str))

    @property
    def identifier(self):
        return self.code

    def _asdict(self):
        return self.identifier

    def _as_markdown(self, level):
        return self._markdown_result(self.name, level)


class HttpVersion(enum.Enum):
    HTTP1_0 = HttpVersionParams(code='http1_0', name='HTTP/1.0')
    HTTP1_1 = HttpVersionParams(code='http1_1', name='HTTP/1.1')
