try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='nymphemeral',
    version='1.3.6',
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
    packages=[
        'nymphemeral',
    ],
    scripts=[
        'scripts/nymphemeral',
    ],
    install_requires=[
        'pyaxo>=0.4.1',
        'python-gnupg>=0.3.5',
        'python-dateutil>=2.2',
    ],
)
