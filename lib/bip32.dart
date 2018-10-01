import 'dart:typed_data';
import 'dart:convert';

import "package:base58check/base58.dart";
import "package:base58check/base58check.dart";
import "package:convert/convert.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/macs/hmac.dart";
import "package:pointycastle/digests/sha256.dart";
import "package:pointycastle/digests/sha512.dart";
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/ecc/api.dart";

final sha256digest = SHA256Digest();
final sha512digest = SHA512Digest();

final curve = ECCurve_secp256k1();

const String alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// FirstHardenedChild is the index of the firxt "harded" child key as per the
/// bip32 spec
const int firstHardenedChild = 0x80000000;

/// PublicKeyCompressedLength is the byte count of a compressed public key
const int publicKeyCompressedLength = 33;

/// The 4 version bytes for the private key serialization as defined in the
/// BIP21 spec
final Uint8List privateKeyVersion = hex.decode("0488ADE4");

/// The 4 version bytes for the public key serialization as defined in the
/// BIP21 spec
final Uint8List publicKeyVersion = hex.decode("0488B21E");

/// From the BIP32 spec. Used when calculating the hmac of the seed
final Uint8List hmacKey = utf8.encoder.convert("Bitcoin seed");

/// From https://github.com/dart-lang/sdk/issues/32803#issuecomment-387405784
BigInt readBytes(Uint8List bytes) {
  BigInt read(int start, int end) {
    if (end - start <= 4) {
      int result = 0;
      for (int i = end - 1; i >= start; i--) {
        result = result * 256 + bytes[i];
      }
      return BigInt.from(result);
    }
    int mid = start + ((end - start) >> 1);
    var result =
        read(start, mid) + read(mid, end) * (BigInt.one << ((mid - start) * 8));
    return result;
  }

  return read(0, bytes.length);
}

class Key {
  // 33 bytes
  Uint8List key;

  // 4 bytes
  Uint8List version;

  // 4 bytes
  Uint8List childNumber;

  // 4 bytes
  Uint8List fingerprint;

  // 32 bytes
  Uint8List chainCode;

  int depth;

  bool isPrivate;

  Key.master(Uint8List seed) {
    HMac hmac = HMac(sha512digest, 128)..init(KeyParameter(hmacKey));
    Uint8List intermediate = hmac.process(seed);

    key = intermediate.sublist(0, 32);
    chainCode = intermediate.sublist(32);
    version = privateKeyVersion;
    depth = 0x0;
    isPrivate = true;
    fingerprint = Uint8List.fromList([0, 0, 0, 0]);
    childNumber = Uint8List.fromList([0, 0, 0, 0]);
  }

  Key.public({
    this.key,
    this.depth,
    this.childNumber,
    this.fingerprint,
    this.chainCode,
  })  : isPrivate = false,
        version = publicKeyVersion;

  Key publicKey() {
    var keyBytes = key;

    if (isPrivate) {
      keyBytes = Key.publicKeyForPrivateKey(keyBytes);
    }

    return Key.public(
      key: keyBytes,
      depth: depth,
      childNumber: childNumber,
      fingerprint: fingerprint,
      chainCode: chainCode,
    );
  }

  // NOTE I honestly don't know why I need to reverse the list.
  static Uint8List publicKeyForPrivateKey(Uint8List key) {
    return ECPublicKey(
            curve.G * readBytes(Uint8List.fromList(key.reversed.toList())),
            curve)
        .Q
        .getEncoded(true);
  }

  Key childKey(int pathFragment) {
    return null;
  }

  List<int> serialize() {
    List<int> serialization = List<int>();
    serialization.addAll(version);
    serialization.add(depth);
    serialization.addAll(fingerprint);
    serialization.addAll(childNumber);
    serialization.addAll(chainCode);
    if (isPrivate) {
      serialization.add(0);
    }
    serialization.addAll(key);

    return serialization;
  }

  @override
  String toString() {
    var payload = serialize();
    var checksum = sha256digest
        .process(sha256digest.process(Uint8List.fromList(payload)))
        .getRange(0, 4);
    payload.addAll(checksum);
    return Base58Codec(alphabet).encode(payload);
  }
}
