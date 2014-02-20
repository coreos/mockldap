#!/usr/bin/env python

from setuptools import setup

try:
    import unittest2  # noqa
except ImportError:
    test_loader = 'unittest:TestLoader'
else:
    test_loader = 'unittest2:TestLoader'


setup(
    name='mockldap',
    version='0.1.5',
    description=u"A simple mock implementation of python-ldap.",
    long_description=open('README').read(),
    url='http://bitbucket.org/psagers/mockldap/',
    author='Peter Sagerson',
    author_email='psagers.pypi@ignorare.net',
    license='BSD',
    packages=['mockldap'],
    package_dir={'': 'src/'},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords=['mock', 'ldap'],
    install_requires=[
        'python-ldap',
        'funcparserlib==0.3.6',
        'mock',
    ],
    extras_require={
        'passlib': ['passlib>=1.6.1'],
    },
    setup_requires=[
        'setuptools>=0.6c11',
    ],
    test_loader=test_loader,
    test_suite='mockldap.tests',
)
