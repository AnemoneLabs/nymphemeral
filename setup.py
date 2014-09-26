try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import platform
from glob import glob
from subprocess import call

distros = ('debian', 'ubuntu')
not_installed = True
if platform.linux_distribution()[0].lower() in distros:
    not_installed = call(['apt-get',  'install', '-y', 'python-tk'])
if not_installed:
    print 'Cannot verify if python-tk is installed. You might have to do it manually'

BASE_DIRECTORY = '/usr/share/nymphemeral'

setup(
    name='nymphemeral',
    version='1.1.0',
    description='An ephemeral nymserver GUI client',
    url='https://github.com/felipedau/nymphemeral',
    author='Felipe Dau',
    author_email='dau.felipe@gmail.com',
    license='GPL',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Communications :: Email',
    ],
    keywords='nymphemeral ephemeral nymserver GUI client',
    packages=[
        'nymphemeral',
    ],
    py_modules=[
        'hsub',
    ],
    scripts=[
        'scripts/nymphemeral',
    ],
    install_requires=[
        'pyaxo>=0.3.5',
        'python-gnupg>=0.3.5',
        'python-dateutil>=2.2',
    ],
    data_files=[
        (BASE_DIRECTORY, ['COPYING']),
        (BASE_DIRECTORY, ['README.rst']),
        (BASE_DIRECTORY + '/db', glob('db/generic.db')),
        (BASE_DIRECTORY + '/connections', glob('connections/*')),
    ],
)