# -*- coding: utf-8 -*-

import abc
import hashlib

import six

from cryptoparser.common.algorithm import Hash
from cryptoparser.common.base import Serializable


class PublicKey(Serializable):
    _HASHLIB_FUNCS = {
        Hash.MD5: hashlib.md5,
        Hash.SHA1: hashlib.sha1,
        Hash.SHA2_256: hashlib.sha256
    }

    @property
    @abc.abstractmethod
    def key_type(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_size(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_digest(cls, hash_type, key_bytes):
        try:
            hashlib_funcs = cls._HASHLIB_FUNCS[hash_type]
        except KeyError as e:
            six.raise_from(NotImplementedError(), e)

        return hashlib_funcs(key_bytes).digest()
