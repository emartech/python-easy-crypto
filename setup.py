#!/usr/bin/env python
from setuptools import setup

setup(
    name='easycrypto',
    description='Provides simple wrappers around Python\'s easycrypto implementation.',
    version='0.0.1',
    author='Emarsys Security',
    author_email='security@emarsys.com',
    license='MIT',
    download_url='https://github.com/emartech/python-easy-easycrypto',
    packages=[
        'easycrypto',
    ],
    zip_safe=True,
    install_requires=[
        'cryptography==2.4.2'
    ],
    tests_require=[
        'unittest-data-provider==1.0.1'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Environment :: Plugins',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security :: Cryptography',
    ],
)