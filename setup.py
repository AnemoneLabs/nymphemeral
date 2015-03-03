try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import platform
from glob import glob
from subprocess import call

distro = platform.linux_distribution()[0].lower()
manager = {
    'debian': 'apt-get',
    'ubuntu': 'apt-get',
    'fedora': 'yum',
}
packages = {
    'python-tk': {'apt-get': 'python-tk', 'yum': 'tkinter'},
}
packages_string = ' '.join(packages.keys())
not_installed = True

if distro in manager:
    packages_list = []
    for package in packages:
        packages_list.append(packages[package][manager[distro]])
    not_installed = call([manager[distro], 'install', '-y'] + packages_list)
    packages_string = ' '.join(packages_list)

if not_installed:
    print 'Cannot verify if all/some of these packages are installed: ' + packages_string + '.You might have to do ' \
                                                                                            'it manually'

BASE_DIRECTORY = '/usr/share/nymphemeral'

setup(
    name='nymphemeral',
    version='1.3.1',
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
        (BASE_DIRECTORY, ['CHANGELOG.md']),
        (BASE_DIRECTORY, ['COPYING']),
        (BASE_DIRECTORY, ['README.rst']),
        (BASE_DIRECTORY + '/db', glob('db/generic.db')),
        (BASE_DIRECTORY + '/connections', glob('connections/*')),
    ],
)