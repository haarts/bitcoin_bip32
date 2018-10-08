# BIP32

An implementation of the [BIP32 spec] for Hierarchical Deterministic Bitcoin
addresses. No [superimposing wallet structure] has been defined.

## Example

You can use this library in two primary ways; one with a serialized public
or private HD key. Or with a hex encoded seed.

Look at the tests to see more elaborate uses.

### With a seed

```
  Chain chain = Chain.seed("some seed");
  ExtendedPrivateKey key = chain.forPath("m/0/100");
```

### Importing a HD private key

```
  Chain chain = Chain.import("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
  ExtendedPrivateKey childKey = chain.forPath("m/0/100");
```

### Importing a HD public key

```
  Chain chain = Chain.import("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
  ExtendedPublic childKey = chain.forPath("M/0/100");
```

Please note that trying to generate a private key from a public key will throw
an exception.


## Exceptions

There is a tiny chance a child key derivation fails. Please catch the
appropriate exceptions in your code.

These exceptions are:
- KeyIsZero
- BiggerThanOrder
- InfiniteKey

## Installing

Add it to your `pubspec.yaml`:

```
dependencies:
  bip32: ^0.1.0
```

## Thanks

Without the guiding code of [go-bip32] and [money-tree] projects this library would have been a significantly bigger struggle.


[BIP32 spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[superimposing wallet structure]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#specification-wallet-structure
[go-bip32]: https://github.com/tyler-smith/go-bip32/
[money-tree]: https://github.com/GemHQ/money-tree/
