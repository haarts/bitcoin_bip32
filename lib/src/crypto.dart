import 'dart:convert';
import 'dart:typed_data';

import 'package:base58check/base58.dart';
import 'package:convert/convert.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/api.dart';
// ignore: implementation_imports
import 'package:pointycastle/src/utils.dart' as utils;

import 'exceptions.dart';

final sha256digest = SHA256Digest();
final sha512digest = SHA512Digest();
final ripemd160digest = RIPEMD160Digest();

/// The Bitcoin curve
final curve = ECCurve_secp256k1();

/// Used for the Base58 encoding.
const String alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/// From the specification (in bytes):
/// 4 version
/// 1 depth
/// 4 fingerprint
/// 4 child number
/// 32 chain code
/// 33 public or private key
const int lengthOfSerializedKey = 78;

/// Length of checksum in bytes
const int lengthOfChecksum = 4;

/// From the specification the length of a private of public key
const int lengthOfKey = 33;

/// FirstHardenedChild is the index of the firxt "hardened" child key as per the
/// bip32 spec
const int firstHardenedChild = 0x80000000;

/// The 4 version bytes for the private key serialization as defined in the
/// BIP21 spec
final Uint8List privateKeyVersion = hex.decode('0488ADE4');

/// The 4 version bytes for the public key serialization as defined in the
/// BIP21 spec
final Uint8List publicKeyVersion = hex.decode('0488B21E');

/// From the BIP32 spec. Used when calculating the hmac of the seed
final Uint8List masterKey = utf8.encoder.convert('Bitcoin seed');

/// AKA 'point(k)' in the specification
ECPoint publicKeyFor(BigInt d) {
  return ECPublicKey(curve.G * d, curve).Q;
}

/// AKA 'ser_P(P)' in the specification
Uint8List compressed(ECPoint q) {
  return q.getEncoded(true);
}

/// AKA 'ser_32(i)' in the specification
Uint8List serializeTo4bytes(int i) {
  var bytes = ByteData(4)..setInt32(0, i, Endian.big);

  return bytes.buffer.asUint8List();
}

/// CKDpriv in the specficiation
ExtendedPrivateKey deriveExtendedPrivateChildKey(
    ExtendedPrivateKey parent, int childNumber) {
  var message = childNumber >= firstHardenedChild
      ? _derivePrivateMessage(parent, childNumber)
      : _derivePublicMessage(parent.publicKey(), childNumber);
  var hash = hmacSha512(parent.chainCode, message);

  var leftSide = utils.decodeBigInt(_leftFrom(hash));
  if (leftSide >= curve.n) {
    throw KeyBiggerThanOrder();
  }

  var childPrivateKey = (leftSide + parent.key) % curve.n;
  if (childPrivateKey == BigInt.zero) {
    throw KeyZero();
  }

  var chainCode = _rightFrom(hash);

  return ExtendedPrivateKey(
    key: childPrivateKey,
    chainCode: chainCode,
    childNumber: childNumber,
    depth: parent.depth + 1,
    parentFingerprint: parent.fingerprint,
  );
}

/// CKDpub in the specification
ExtendedPublicKey deriveExtendedPublicChildKey(
    ExtendedPublicKey parent, int childNumber) {
  if (childNumber >= firstHardenedChild) {
    throw InvalidChildNumber();
  }

  var message = _derivePublicMessage(parent, childNumber);
  var hash = hmacSha512(parent.chainCode, message);

  var leftSide = utils.decodeBigInt(_leftFrom(hash));
  if (leftSide >= curve.n) {
    throw KeyBiggerThanOrder();
  }

  var childPublicKey = publicKeyFor(leftSide) + parent.q;
  if (childPublicKey.isInfinity) {
    throw KeyInfinite();
  }

  return ExtendedPublicKey(
    q: childPublicKey,
    chainCode: _rightFrom(hash),
    childNumber: childNumber,
    depth: parent.depth + 1,
    parentFingerprint: parent.fingerprint,
  );
}

Uint8List _paddedEncodedBigInt(BigInt i) {
  var fullLength = Uint8List(lengthOfKey - 1);
  var encodedBigInt = utils.encodeBigInt(i);
  fullLength.setAll(fullLength.length - encodedBigInt.length, encodedBigInt);

  return fullLength;
}

Uint8List _derivePrivateMessage(ExtendedPrivateKey key, int childNumber) {
  var message = Uint8List(37)
    ..setAll(1, _paddedEncodedBigInt(key.key))
    ..setAll(33, serializeTo4bytes(childNumber));

  return message;
}

Uint8List _derivePublicMessage(ExtendedPublicKey key, int childNumber) {
  var message = Uint8List(37)
    ..setAll(0, compressed(key.q))
    ..setAll(33, serializeTo4bytes(childNumber));

  return message;
}

/// This function returns a list of length 64. The first half is the key, the
/// second half is the chain code.
Uint8List hmacSha512(Uint8List key, Uint8List message) {
  var hmac = HMac(sha512digest, 128)..init(KeyParameter(key));
  return hmac.process(message);
}

/// Double hash the data: RIPEMD160(SHA256(data))
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
bool equal(Iterable a, Iterable b) {
  if (a.length != b.length) {
    return false;
  }

  for (var i = 0; i < a.length; i++) {
    if (a.elementAt(i) != b.elementAt(i)) {
      return false;
    }
  }

  return true;
}

// NOTE yikes, what a dance, surely I'm overlooking something
Uint8List sublist(Uint8List list, int start, int end) {
  return Uint8List.fromList(list.getRange(start, end).toList());
}

/// Abstract class on which [ExtendedPrivateKey] and [ExtendedPublicKey] are based.
abstract class ExtendedKey {
  ExtendedKey({
    this.version,
    this.depth,
    this.childNumber,
    this.chainCode,
    this.parentFingerprint,
  });

  /// Take a HD key serialized according to the spec and deserialize it.
  ///
  /// Works for both private and public keys.
  factory ExtendedKey.deserialize(String key) {
    var decodedKey = Base58Codec(alphabet).decode(key);
    if (decodedKey.length != lengthOfSerializedKey + lengthOfChecksum) {
      throw InvalidKeyLength(
          decodedKey.length, lengthOfSerializedKey + lengthOfChecksum);
    }

    if (equal(decodedKey.getRange(0, 4), privateKeyVersion)) {
      return ExtendedPrivateKey.deserialize(decodedKey);
    }

    return ExtendedPublicKey.deserialize(decodedKey);
  }

  /// 32 bytes
  Uint8List chainCode;

  int childNumber;

  int depth;

  /// 4 bytes
  final Uint8List version;

  /// 4 bytes
  Uint8List parentFingerprint;

  /// Returns the first 4 bytes of the hash160 compressed public key.
  Uint8List get fingerprint;

  /// Returns the public key assocated with the extended key.
  ///
  /// In case of [ExtendedPublicKey] returns self.
  ExtendedPublicKey publicKey();

  List<int> _serialize() {
    return [
      ...version,
      depth,
      ...parentFingerprint,
      ...serializeTo4bytes(childNumber),
      ...chainCode,
      ..._serializedKey()
    ];
  }

  List<int> _serializedKey();

  /// Used to verify deserialized keys.
  bool verifyChecksum(Uint8List externalChecksum) {
    return equal(_checksum(), externalChecksum.toList());
  }

  Iterable<int> _checksum() {
    return sha256digest
        .process(sha256digest.process(Uint8List.fromList(_serialize())))
        .getRange(0, 4);
  }

  /// Returns the string representation of this extended key. This can be
  /// written to disk for future deserializion.
  @override
  String toString() {
    var payload = _serialize()..addAll(_checksum());

    return Base58Codec(alphabet).encode(payload);
  }
}

/// An extended private key as defined by the BIP32 specification.
///
/// In the lingo of the spec this is a `(k, c)`.
/// This can be used to generate a extended public key or further child keys.
/// Note that the spec talks about a 'neutered' key, this is the public key
/// associated with a private key.
class ExtendedPrivateKey extends ExtendedKey {
  ExtendedPrivateKey({
    this.key,
    int depth,
    int childNumber,
    Uint8List chainCode,
    Uint8List parentFingerprint,
  }) : super(
            version: privateKeyVersion,
            depth: depth,
            childNumber: childNumber,
            parentFingerprint: parentFingerprint,
            chainCode: chainCode);

  ExtendedPrivateKey.master(Uint8List seed)
      : super(version: privateKeyVersion) {
    var hash = hmacSha512(masterKey, seed);
    key = utils.decodeBigInt(_leftFrom(hash));
    chainCode = _rightFrom(hash);
    depth = 0;
    childNumber = 0;
    parentFingerprint = Uint8List.fromList([0, 0, 0, 0]);
  }

  factory ExtendedPrivateKey.deserialize(Uint8List key) {
    var extendedPrivateKey = ExtendedPrivateKey(
      depth: key[4],
      parentFingerprint: sublist(key, 5, 9),
      childNumber: ByteData.view(sublist(key, 9, 13).buffer).getInt32(0),
      chainCode: sublist(key, 13, 45),
      key: utils.decodeBigInt(sublist(key, 46, 78)),
    );

    if (!extendedPrivateKey.verifyChecksum(sublist(key, lengthOfSerializedKey,
        lengthOfSerializedKey + lengthOfChecksum))) {
      throw InvalidChecksum();
    }

    return extendedPrivateKey;
  }

  BigInt key;

  @override
  ExtendedPublicKey publicKey() {
    return ExtendedPublicKey(
      q: publicKeyFor(key),
      depth: depth,
      childNumber: childNumber,
      chainCode: chainCode,
      parentFingerprint: parentFingerprint,
    );
  }

  @override
  Uint8List get fingerprint => publicKey().fingerprint;

  @override
  List<int> _serializedKey() {
    var serialization = Uint8List(lengthOfKey);
    serialization[0] = 0;
    var encodedKey = _paddedEncodedBigInt(key);
    serialization.setAll(1, encodedKey);

    return serialization.toList();
  }
}

/// An extended public key as defined by the BIP32 specification.
///
/// In the lingo of the spec this is a `(K, c)`.
/// This can be used to generate further public child keys only.
class ExtendedPublicKey extends ExtendedKey {
  ExtendedPublicKey({
    this.q,
    depth,
    childNumber,
    chainCode,
    parentFingerprint,
  }) : super(
            version: publicKeyVersion,
            depth: depth,
            childNumber: childNumber,
            parentFingerprint: parentFingerprint,
            chainCode: chainCode);

  factory ExtendedPublicKey.deserialize(Uint8List key) {
    var extendedPublickey = ExtendedPublicKey(
      depth: key[4],
      parentFingerprint: sublist(key, 5, 9),
      childNumber: ByteData.view(sublist(key, 9, 13).buffer).getInt32(0),
      chainCode: sublist(key, 13, 45),
      q: _decodeCompressedECPoint(sublist(key, 45, 78)),
    );

    if (!extendedPublickey.verifyChecksum(sublist(key, 78, 82))) {
      throw InvalidChecksum();
    }

    return extendedPublickey;
  }

  ECPoint q;

  @override
  Uint8List get fingerprint {
    var identifier = hash160(compressed(q));
    return Uint8List.view(identifier.buffer, 0, 4);
  }

  @override
  ExtendedPublicKey publicKey() {
    return this;
  }

  @override
  List<int> _serializedKey() {
    return compressed(q).toList();
  }

  static ECPoint _decodeCompressedECPoint(Uint8List encodedPoint) {
    return curve.curve.decodePoint(encodedPoint.toList());
  }
}

//ignore_for_file: avoid_print
void debug(List<int> payload) {
  print('version: ${payload.getRange(0, 4)}');
  print('depth: ${payload.getRange(4, 5)}');
  print('parent fingerprint: ${payload.getRange(5, 9)}');
  print('childNumber: ${payload.getRange(9, 13)}');
  print('chaincode: ${payload.getRange(13, 46)}');
  print('key: ${payload.getRange(46, 78)}');
  print('checksum: ${payload.getRange(78, 82)}');
}
