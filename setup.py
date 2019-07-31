#!/usr/bin/env python
from setuptools import setup

setup(
    name='easycrypto',
    description='Provides simple wrappers around Python\'s easycrypto implementation.',
    version='1.1.0',
    author='Emarsys Security',
    author_email='security@emarsys.com',
    license='MIT',
    url='https://pypi.org/project/easycrypto/',
    download_url='https://github.com/emartech/python-easy-crypto',
    packages=[
        'easycrypto',
    ],
    zip_safe=True,
    install_requires=[
        'cryptography==2.7'
    ],
    extras_require={
        'dev': [
            'unittest-data-provider==1.0.1'
        ]
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Environment :: Plugins',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security :: Cryptography',
    ],
)
