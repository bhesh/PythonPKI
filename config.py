#!/usr/bin/python
#
# Configuration loader
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
import os, json, re
import cert, ocsp


FILE_MATCH = re.compile(r'^.*.conf$')


class ConfigLoader:

    def __init__(self, dirname, filter=None):
        self.dirname = dirname
        self.filter = filter

    def load(self, filename):
        with open(os.path.join(self.dirname, filename), 'r') as f:
            return json.load(f)

    def __iter__(self):
        files = [name for name in os.listdir(self.dirname) if not os.path.isdir(os.path.join(self.dirname, name)) and FILE_MATCH.match(name)]
        for filename in files:
            if not self.filter or self.filter.match(filename):
                yield self.load(filename)

