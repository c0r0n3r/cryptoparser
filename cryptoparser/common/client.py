#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import six
import socket

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.utils import get_leaf_classes


@six.add_metaclass(abc.ABCMeta)
class L7ClientBase(object):
    _REGISTERED_CLIENTS = []
    _DEFAULT_TIMEOUT = 2

    def __init__(self, host, port, timeout=None):
        self._host = host
        self._port = port
        self._socket = None
        self._buffer = bytearray()
        self._timeout = self._DEFAULT_TIMEOUT if timeout is None else timeout

    @classmethod
    def __subclasshook__(cls, subclass):
        cls._REGISTERED_CLIENTS.append(subclass)

        return NotImplemented

    @classmethod
    def get_clients(cls):
        return list(cls._REGISTERED_CLIENTS)

    def _close(self):
        self._socket.close()
        self._socket = None

    def send(self, sendable_bytes):
        total_sent_byte_num = 0
        while total_sent_byte_num < len(sendable_bytes):
            actual_sent_byte_num = self._socket.send(sendable_bytes[total_sent_byte_num:])
            if actual_sent_byte_num == 0:
                raise IOError()
            total_sent_byte_num = total_sent_byte_num + actual_sent_byte_num

        return total_sent_byte_num

    def receive(self, receivable_byte_num):
        total_received_byte_num = 0
        while total_received_byte_num < receivable_byte_num:
            try:
                actual_received_bytes = self._socket.recv(min(receivable_byte_num - total_received_byte_num, 1024))
                self._buffer += actual_received_bytes
                total_received_byte_num += len(actual_received_bytes)
            except socket.error:
                actual_received_bytes = None

            if not actual_received_bytes:
                raise NotEnoughData(receivable_byte_num - total_received_byte_num)

    def receive_at_most(self, receivable_byte_num):
        try:
            self.receive(receivable_byte_num)
        except NotEnoughData as e:
            if e.bytes_needed == receivable_byte_num:
                raise e

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def buffer(self):
        return bytearray(self._buffer)

    def flush_buffer(self, byte_num=None):
        if byte_num is None:
            byte_num = len(self._buffer)

        self._buffer = self._buffer[byte_num:]

    @classmethod
    def from_scheme(cls, scheme, host, port=None):
        for client_class in get_leaf_classes(L7ClientBase):
            if client_class.get_scheme() == scheme:
                port = client_class.get_default_port() if port is None else port
                return client_class(host, port)
        else:
            raise ValueError()

    @classmethod
    def get_supported_schemes(cls):
        return set([leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(cls)])

    @abc.abstractmethod
    def _connect(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()


class L7ClientTcp(L7ClientBase):
    def _connect(self):
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        sock.settimeout(self._timeout)
        return sock
