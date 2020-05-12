import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'crypto.dart';
import 'exceptions.dart';

/// Use this class to generate extended keys. You can create an instance of
/// this class with either a serialized extended key ([Chain.import]) or a
/// hex encoded master seed ([Chain.seed]).
class Chain {
  /// Create a chain based on a hex seed.
  Chain.seed(String seed) {
    Uint8List seedBytes = hex.decoder.convert(seed);
    root = ExtendedPrivateKey.master(seedBytes);
  }

  /// Create a chain based on a serialized private or public key.
  Chain.import(String key) {
    root = ExtendedKey.deserialize(key);
  }

  static const String _hardenedSuffix = "'";
  static const String _privateKeyPrefix = 'm';
  static const String _publicKeyPrefix = 'M';

  /// The root out of which all keys can be derived.
  ExtendedKey root;

  bool get isPrivate => root is ExtendedPrivateKey;

  /// Derives a key based on a path.
  ///
  /// A path is a slash delimited string starting with 'm' for private key and
  /// 'M' for a public key. Hardened keys are indexed with a tick.
  /// Example: "m/100/1'".
  /// This is the first Hardened private extended key on depth 2.
  ExtendedKey forPath(String path) {
    _validatePath(path);

    var wantsPrivate = path[0] == _privateKeyPrefix;
    var children = _parseChildren(path);

    if (children.isEmpty) {
      if (wantsPrivate) {
        return root;
      }
      return root.publicKey();
    }

    dynamic derivationFunction = wantsPrivate
        ? deriveExtendedPrivateChildKey
        : deriveExtendedPublicChildKey;

    return children.fold(root, (previousKey, childNumber) {
      return derivationFunction(previousKey, childNumber);
    });
  }

  void _validatePath(String path) {
    var kind = path.split('/').removeAt(0);

    if (![_privateKeyPrefix, _publicKeyPrefix].contains(kind)) {
      throw InvalidPath("Path needs to start with 'm' or 'M'");
    }

    if (kind == _privateKeyPrefix && root is ExtendedPublicKey) {
      throw InvalidPath('Cannot derive private key from public master');
    }
  }

  Iterable<int> _parseChildren(String path) {
    var explodedList = path.split('/')
      ..removeAt(0)
      ..removeWhere((child) => child == '');

    return explodedList.map((pathFragment) {
      if (pathFragment.endsWith(_hardenedSuffix)) {
        pathFragment = pathFragment.substring(0, pathFragment.length - 1);
        return int.parse(pathFragment) + firstHardenedChild;
      } else {
        return int.parse(pathFragment);
      }
    });
  }
}
