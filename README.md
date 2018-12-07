# EasyCrypto

[![Build Status](https://travis-ci.org/emartech/python-easy-crypto.svg?branch=master)](https://travis-ci.org/emartech/python-easy-crypto)

Provides simple wrappers around Python [cryptography](https://cryptography.io/en/latest/) module. It is secure by default and compatible with [the easy-crypto node module](https://www.npmjs.com/package/@emartech/easy-crypto).

## Example usage

```python
from easycrypto import Crypto

plaintext = 'mysecretdata'
password = 'mypassword'

encrypted = Crypto.encrypt(password, plaintext)
decrypted = Crypto.decrypt(password, encrypted)
assert encrypted == decrypted
```

## The crypto parts

The library is only a thin wrapper of python's own [cryptography](https://cryptography.io/en/latest/) module. It uses well known and battle tested encryption techniques. It provides a convenient wrapper around these functions, taking away the details of using encryption correctly. Feel free to explore the source!

### Encryption process

1. A random so called _password salt_ (`12` random bytes) is used to create the `256 bit` long encryption key from the `password` using `pbkdf2` and `10000` as iteration count.
2. The `plaintext` is encrypted using `aes-256-gcm` with the generated key and a `12` bytes long random _initialization vector_. The resulted _ciphertext_ contains built-in integrity check as well.
3. To enable decryption, the following data is concatenated into a buffer: _password salt_, _initialization vector_, _ciphertext_.
4. It encodes the whole buffer using `base64` and returns it.

### Decryption process

1. It decodes the `base64` input to bytes
2. It slices this data into: _password salt_, _initialization vector_, _ciphertext_.
3. The _password salt_ and the `password` are used to generate the `256 bit` long encryption key using `pbkdf2` and `10000` as iteration count (same as in encryption process).
4. The _ciphertext_ is decrypted using `aes-256-gcm` with the generated key and the _initialization vector_. During encryption the integrity of the data is also verified.

## Found a bug? Have a comment?

Please find us, we would love your feedback!

## Release

Tag your commit with x.y.z, then if all tests pass x.y.z version will be released on Pypi.
