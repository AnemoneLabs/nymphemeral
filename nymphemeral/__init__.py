"""
nymphemeral - an ephemeral nym GUI client

Encryption is done using python-gnupg and pyaxo from
https://pypi.python.org/pypi/python-gnupg/
https://github.com/rxcomm/pyaxo

Messages are retrieved from a.a.m using aampy.py and hsub.py
from https://github.com/rxcomm/aampy

Messages dates are parsed using python-dateutil 2.2 from
https://pypi.python.org/pypi/python-dateutil

Copyright (C) 2014-2015 by Felipe Dau <dau.felipe@gmail.com> and
David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

For more information, see https://github.com/felipedau/nymphemeral
"""
import logging
import os

from ._version import get_versions


__author__ = 'Felipe Dau and David R. Andersen'
__license__ = 'GPL'
__version__ = get_versions()['version']
__status__ = 'Beta'

LINESEP = '\n'
PATHSEP = os.path.sep
FORMAT = '%(levelname)s - %(name)s: %(message)s'

logger = logging.getLogger()

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(handler)

# let gnupg log only errors
logging.getLogger('gnupg').setLevel(logging.ERROR)

del get_versions
