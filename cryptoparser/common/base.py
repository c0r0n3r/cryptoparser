#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum
import json

from typing import TypeVar


T = TypeVar('T')


def _default(self, obj):
    if isinstance(obj, enum.Enum) and hasattr(obj.value, '_asdict'):
        return { obj.name: obj.value._asdict() }
    elif isinstance(obj, JSONSerializable) and hasattr(obj, 'as_json'):
        return obj.as_json()
    elif hasattr(obj, '__dict__'):
        return { name: value for name, value in obj.__dict__.items() if not name.startswith('_') }

    return str(obj)

_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default


class JSONSerializable(object):
    def as_json(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return self.as_json()
