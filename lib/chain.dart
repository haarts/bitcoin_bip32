import 'dart:convert';
import 'dart:typed_data';

import "package:convert/convert.dart";

import "bip32.dart";
import "exceptions.dart";

class Chain {
  static const String hardenedSuffix = "'";

  ExtendedKey root;

  Chain.seed(String seed) {
    Uint8List seedBytes = hex.decoder.convert(seed);
    root = ExtendedPrivateKey.master(seedBytes);
  }

  Chain.import(String key) {
    root = ExtendedKey.deserialize(key);
  }

  bool get isPrivate => root is ExtendedPrivateKey;

  ExtendedKey forPath(String path) {
    _validatePath(path);

    bool wantsPrivate = path[0] == 'm';
    Iterable<int> children = _parseChildren(path);

    if (children.isEmpty) {
      if (wantsPrivate) {
        return root;
      }
      return root.publicKey();
    }

    dynamic derivationFunction = wantsPrivate
        ? deriveExtendedPrivateChildKey
        : deriveExtendedPublicChildKey;

    return children.fold(root, (ExtendedKey previousKey, int childNumber) {
      return derivationFunction(previousKey, childNumber);
    });
  }

  void _validatePath(String path) {
    String kind = path.split("/").removeAt(0);

    if (!["m", "M"].contains(kind)) {
      throw InvalidPath("Path needs to start with 'm' or 'M'");
    }

    if (kind == "m" && root is ExtendedPublicKey) {
      throw InvalidPath("Cannot derive private key from public master");
    }
  }

  Iterable<int> _parseChildren(String path) {
    List<String> explodedList = path.split("/")
      ..removeAt(0)
      ..removeWhere((child) => child == "");

    return explodedList.map((String pathFragment) {
      if (pathFragment.endsWith(hardenedSuffix)) {
        pathFragment = pathFragment.substring(0, pathFragment.length - 1);
        return int.parse(pathFragment) + firstHardenedChild;
      } else {
        return int.parse(pathFragment);
      }
    });
  }
}
