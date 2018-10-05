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

import "exceptions.dart";

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
const int lengthOfSerializedKey = 82;

/// From the specification the length of a private of public key
const int lengthOfKey = 33;

/// FirstHardenedChild is the index of the firxt "hardened" child key as per the
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
ECPoint publicKeyFor(BigInt d) {
  return ECPublicKey(curve.G * d, curve).Q;
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
      ? _derivePrivateMessage(key, childNumber)
      : _derivePublicMessage(key.publicKey(), childNumber);
  Uint8List hash = hmacSha512(key.chainCode, message);

  BigInt leftSide = utils.decodeBigInt(_leftFrom(hash));
  if (leftSide >= curve.n) {
    throw BiggerThanOrder();
  }

  BigInt childPrivateKey = (leftSide + key.key) % curve.n;
  if (childPrivateKey == BigInt.zero) {
    throw KeyIsZero();
  }

  Uint8List chainCode = _rightFrom(hash);

  return ExtendedPrivateKey(
    key: childPrivateKey,
    chainCode: chainCode,
    childNumber: childNumber,
    depth: key.depth + 1,
    parentFingerprint: key.fingerprint,
  );
}

/// CKDpub
ExtendedPublicKey deriveExtendedPublicChildKey(
    ExtendedPublicKey key, int childNumber) {
  if (childNumber >= firstHardenedChild) {
    throw InvalidChildNumber();
  }

  Uint8List message = _derivePublicMessage(key, childNumber);
  Uint8List hash = hmacSha512(key.chainCode, message);

  BigInt leftSide = utils.decodeBigInt(_leftFrom(hash));
  if (leftSide >= curve.n) {
    throw BiggerThanOrder();
  }

  // TODO check if childPublicKey is infinite
  ECPoint childPublicKey =
      publicKeyFor(leftSide) + key.q;

  return ExtendedPublicKey(
    q: childPublicKey,
    chainCode: _rightFrom(hash),
    childNumber: childNumber,
    depth: key.depth + 1,
    parentFingerprint: key.fingerprint,
  );
}

Uint8List _paddedEncodedBigInt(BigInt i) {
  Uint8List fullLength = Uint8List(lengthOfKey - 1);
  Uint8List encodedBigInt = utils.encodeBigInt(i);
  fullLength.setAll(fullLength.length - encodedBigInt.length, encodedBigInt);

  return fullLength;
}

Uint8List _derivePrivateMessage(ExtendedPrivateKey key, int childNumber) {
  Uint8List message = Uint8List(37);
  message[0] = 0;
  message.setAll(1, _paddedEncodedBigInt(key.key));
  message.setAll(33, serializeTo4bytes(childNumber));

  return message;
}

Uint8List _derivePublicMessage(ExtendedPublicKey key, int childNumber) {
  Uint8List message = Uint8List(37);
  message.setAll(0, compressed(key.q));
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

abstract class ExtendedKey {
  // 32 bytes
  Uint8List chainCode;

  int childNumber;

  int depth;

  // 4 bytes
  final Uint8List version;

  // 4 bytes
  Uint8List parentFingerprint;

  ExtendedKey({
    this.version,
    this.depth,
    this.childNumber,
    this.chainCode,
    this.parentFingerprint,
  });

  factory ExtendedKey.deserialize(String key) {
    List<int> decodedKey = Base58Codec(alphabet).decode(key);
    if (decodedKey.length != lengthOfSerializedKey) {
      throw Exception("key not of length $lengthOfSerializedKey");
    }

    if (equal(decodedKey.getRange(0, 4), privateKeyVersion)) {
      return ExtendedPrivateKey.deserialize(decodedKey);
    }

    return ExtendedPublicKey.deserialize(decodedKey);
  }

  Uint8List get fingerprint;

  List<int> _serialize() {
    List<int> serialization = List<int>();
    serialization.addAll(version);
    serialization.add(depth);
    serialization.addAll(parentFingerprint);
    serialization.addAll(serializeTo4bytes(childNumber));
    serialization.addAll(chainCode);
    serialization.addAll(_serializedKey());

    return serialization;
  }

  List<int> _serializedKey();

  bool verifyChecksum(Uint8List externalChecksum) {
    return equal(_checksum(), externalChecksum.toList());
  }

  Iterable<int> _checksum() {
    return sha256digest
        .process(sha256digest.process(Uint8List.fromList(_serialize())))
        .getRange(0, 4);
  }

  @override
  String toString() {
    List<int> payload = _serialize();
    payload.addAll(_checksum());

    return Base58Codec(alphabet).encode(payload);
  }
}

class ExtendedPrivateKey extends ExtendedKey {
  BigInt key;

  ExtendedPrivateKey({
    BigInt this.key,
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
    Uint8List hash = hmacSha512(masterKey, seed);
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

    if (!extendedPrivateKey.verifyChecksum(sublist(key, 78, 82))) {
      throw InvalidChecksum();
    }

    return extendedPrivateKey;
  }

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
    Uint8List serialization = Uint8List(lengthOfKey);
    serialization[0] = 0;
    Uint8List encodedKey = _paddedEncodedBigInt(key);
    serialization.setAll(1, encodedKey);

    return serialization.toList();
  }
}

class ExtendedPublicKey extends ExtendedKey {
  ECPoint q;

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

  @override
  Uint8List get fingerprint {
    Uint8List identifier = hash160(compressed(q));
    return Uint8List.view(identifier.buffer, 0, 4);
  }

  @override
  List<int> _serializedKey() {
    return compressed(q).toList();
  }

  static ECPoint _decodeCompressedECPoint(Uint8List encodedPoint) {
    return curve.curve.decodePoint(encodedPoint.toList());
  }
}

void debug(List<int> payload) {
  print("version: ${payload.getRange(0, 4)}");
  print("depth: ${payload.getRange(4, 5)}");
  print("parent fingerprint: ${payload.getRange(5, 9)}");
  print("childNumber: ${payload.getRange(9, 13)}");
  print("chaincode: ${payload.getRange(13, 46)}");
  print("key: ${payload.getRange(46, 78)}");
  print("checksum: ${payload.getRange(78, 82)}");
}
