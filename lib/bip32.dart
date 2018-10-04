import 'dart:typed_data';
import 'dart:convert';

import "package:base58check/base58.dart";
import "package:base58check/base58check.dart";
import "package:convert/convert.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/macs/hmac.dart";
import "package:pointycastle/digests/sha256.dart";
import "package:pointycastle/digests/sha512.dart";
import "package:pointycastle/digests/ripemd160.dart";
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/src/utils.dart" as utils;

final sha256digest = SHA256Digest();
final sha512digest = SHA512Digest();
final ripemd160digest = RIPEMD160Digest();

final curve = ECCurve_secp256k1();

const String alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// From the specficiation:
/// 4 version
/// 1 depth
/// 4 fingerprint
/// 4 child number
/// 32 chain code
/// 33 public or private key
const int lengthOfKey = 82;

/// FirstHardenedChild is the index of the firxt "harded" child key as per the
/// bip32 spec
const int firstHardenedChild = 0x80000000;

/// The 4 version bytes for the private key serialization as defined in the
/// BIP21 spec
final Uint8List privateKeyVersion = hex.decode("0488ADE4");

/// The 4 version bytes for the public key serialization as defined in the
/// BIP21 spec
final Uint8List publicKeyVersion = hex.decode("0488B21E");

/// From the BIP32 spec. Used when calculating the hmac of the seed
final Uint8List masterKey = utf8.encoder.convert("Bitcoin seed");

/// AKA 'point(k)' in the specification
ECPoint publicKeyFor(Uint8List encodedInt) {
  return ECPublicKey(curve.G * utils.decodeBigInt(encodedInt), curve).Q;
}

/// AKA 'ser_P(P)' in the specification
Uint8List compressed(ECPoint q) {
  return q.getEncoded(true);
}

/// AKA 'ser_32(i)' in the specification
Uint8List serializeTo4bytes(int i) {
  ByteData bytes = ByteData(4);
  bytes.setInt32(0, i, Endian.big);

  return bytes.buffer.asUint8List();
}

/// CKDpriv
ExtendedPrivateKey deriveExtendedPrivateChildKey(
    ExtendedPrivateKey key, int childNumber) {
  Uint8List message = childNumber >= firstHardenedChild
      ? _derivePrivateMessage(key.key, childNumber)
      : _derivePublicMessage(key.key, childNumber);
  Uint8List hash = hmacSha512(key.chainCode, message);

  // TODO iff leftSide bigger than order throw exception
  BigInt leftSide = utils.decodeBigInt(_leftFrom(hash));

  // TODO iff childPrivateKey is zero throw exception
  BigInt childPrivateKey = (leftSide + utils.decodeBigInt(key.key)) % curve.n;

  Uint8List chainCode = _rightFrom(hash);

  return ExtendedPrivateKey(
    key: utils.encodeBigInt(childPrivateKey),
    chainCode: chainCode,
    childNumber: childNumber,
    depth: key.depth + 1,
  );
}

Uint8List _derivePrivateMessage(Uint8List key, int childNumber) {
  Uint8List message = Uint8List(37);
  message[0] = 0;
  message.setAll(1, key);
  message.setAll(33, serializeTo4bytes(childNumber));

  return message;
}

// TODO iff childNumber >= firstHardenedChild throw exception
/// CKDpub
ExtendedPublicKey deriveExtendedPublicChildKey(
    ExtendedPublicKey key, int childNumber) {
  Uint8List message = _derivePublicMessage(key.key, childNumber);
  Uint8List hash = hmacSha512(key.chainCode, message);

  // TODO iff leftSide bigger than order throw exception
  BigInt leftSide = utils.decodeBigInt(_leftFrom(hash));

  Uint8List childPublicKey =
      (publicKeyFor(_leftFrom(hash)) + publicKeyFor(key.key)).getEncoded(true);

  return ExtendedPublicKey(
    key: childPublicKey,
    chainCode: _rightFrom(hash),
    childNumber: childNumber,
    depth: key.depth + 1,
  );
}

Uint8List _derivePublicMessage(Uint8List key, int childNumber) {
  Uint8List message = Uint8List(37);
  message.setAll(0, key);
  message.setAll(33, serializeTo4bytes(childNumber));

  return message;
}

/// This function returns a list of length 64. The first half is the key, the
/// second half is the chain code.
Uint8List hmacSha512(Uint8List key, Uint8List message) {
  HMac hmac = HMac(sha512digest, 128)..init(KeyParameter(key));
  return hmac.process(message);
}

Uint8List hash160(Uint8List data) {
  return ripemd160digest.process(sha256digest.process(data));
}

Uint8List _leftFrom(Uint8List list) {
  return list.sublist(0, 32);
}

Uint8List _rightFrom(Uint8List list) {
  return list.sublist(32);
}

// NOTE wow, this is annoying
bool equal(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }

  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }

  return true;
}

abstract class ExtendedKey {
  // 33 bytes, big endian
  Uint8List key;

  // 32 bytes
  Uint8List chainCode;

  int childNumber;

  int depth;

  // 4 bytes
  final Uint8List version;

  bool get isMaster => depth == 0;

  ExtendedKey({
    this.version,
    this.key,
    this.depth,
    this.childNumber,
    this.chainCode,
  });

  factory ExtendedKey.deserialize(String key) {
    List<int> decodedKey = Base58Codec(alphabet).decode(key);
    if (decodedKey.length != lengthOfKey) {
      throw Exception("key not of length $lengthOfKey");
    }

    if (equal(decodedKey.getRange(0, 4).toList(), privateKeyVersion.toList())) {
      return ExtendedPrivateKey.deserialize(decodedKey);
    }

    return ExtendedPublicKey.deserialize(decodedKey);
  }

  Uint8List get fingerprint {
    if (isMaster) {
      return Uint8List.fromList([0, 0, 0, 0]);
    }

    Uint8List hash = hash160(compressed(publicKeyFor(key)));
    return Uint8List.view(hash.buffer, 0, 4);
  }

  List<int> _serialize() {
    List<int> serialization = List<int>();
    serialization.addAll(version);
    serialization.add(depth);
    serialization.addAll(fingerprint);
    serialization.addAll(serializeTo4bytes(childNumber));
    serialization.addAll(chainCode);
    serialization.addAll(_serializedKey());

    return serialization;
  }

  List<int> _serializedKey();

  @override
  String toString() {
    List<int> payload = _serialize();
    var checksum = sha256digest
        .process(sha256digest.process(Uint8List.fromList(payload)))
        .getRange(0, 4);
    payload.addAll(checksum);

    return Base58Codec(alphabet).encode(payload);
  }
}

class ExtendedPrivateKey extends ExtendedKey {
  ExtendedPrivateKey({
    Uint8List key,
    int depth,
    int childNumber,
    Uint8List chainCode,
  }) : super(
            version: privateKeyVersion,
            key: key,
            depth: depth,
            childNumber: childNumber,
            chainCode: chainCode);

  ExtendedPrivateKey.master(Uint8List seed)
      : super(version: privateKeyVersion) {
    Uint8List hash = hmacSha512(masterKey, seed);
    key = _leftFrom(hash);
    chainCode = _rightFrom(hash);
    depth = 0;
    childNumber = 0;
  }

  factory ExtendedPrivateKey.deserialize(Uint8List key) {
    return ExtendedPrivateKey(
      depth: key[4],
      childNumber:
          ByteData.view(Uint8List.fromList(key.getRange(9, 13).toList()).buffer)
              .getInt32(0),
      key: Uint8List.fromList(key.getRange(46, 78).toList()),
      chainCode: Uint8List.fromList(key.getRange(13, 45).toList()),
    );
  }

  ExtendedPublicKey publicKey() {
    return ExtendedPublicKey(
      key: compressed(publicKeyFor(key)),
      depth: depth,
      childNumber: childNumber,
      chainCode: chainCode,
    );
  }

  @override
  List<int> _serializedKey() {
    List<int> serialization = [0];
    serialization.addAll(key);

    return serialization;
  }
}

class ExtendedPublicKey extends ExtendedKey {
  // 4 bytes
  final Uint8List version = publicKeyVersion;

  ExtendedPublicKey({
    key,
    depth,
    childNumber,
    chainCode,
  }) : super(
            version: publicKeyVersion,
            key: key,
            depth: depth,
            childNumber: childNumber,
            chainCode: chainCode);

  factory ExtendedPublicKey.deserialize(Uint8List key) {
    return ExtendedPublicKey(
      depth: key[4],
      childNumber:
          ByteData.view(Uint8List.fromList(key.getRange(9, 13).toList()).buffer)
              .getInt32(0),
      key: Uint8List.fromList(key.getRange(46, 78).toList()),
      chainCode: Uint8List.fromList(key.getRange(13, 45).toList()),
    );
  }

  @override
  List<int> _serializedKey() {
    return key.toList();
  }
}
