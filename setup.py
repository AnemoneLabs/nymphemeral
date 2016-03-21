from setuptools import setup, find_packages

import versioneer


setup(
    name='nymphemeral',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='An ephemeral nym GUI client',
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
    packages=find_packages(),
    install_requires=[
        'pyaxo>=0.4.1',
        'pycrypto>=2.1.0',
        'python-gnupg>=0.3.5',
        'python-dateutil>=2.2',
    ],
    entry_points={
        'console_scripts': [
            'nymphemeral = nymphemeral.__main__:main',
        ],
    },
    package_data={
        'nymphemeral.keyring': ['*.asc'],
    },
)
