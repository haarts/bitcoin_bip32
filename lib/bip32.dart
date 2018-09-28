import 'dart:typed_data';
import 'dart:convert';

import "package:base58check/base58.dart";
import "package:convert/convert.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/macs/hmac.dart";
import "package:pointycastle/digests/sha512.dart";

final sha512digest = SHA512Digest();

const String alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// FirstHardenedChild is the index of the firxt "harded" child key as per the
/// bip32 spec
const int firstHardenedChild = 0x80000000;

/// PublicKeyCompressedLength is the byte count of a compressed public key
const int publicKeyCompressedLength = 33;

/// The 4 version bytes for the private key serialization as defined in the
/// BIP21 spec
final Uint8List privateKeyVersionBytes = hex.decode("0488ADE4");

/// The 4 version bytes for the public key serialization as defined in the
/// BIP21 spec
final Uint8List publicKeyVersionBytes = hex.decode("0488B21E");

/// From the BIP32 spec. Used when ... words...
final Uint8List hmacKey = utf8.encoder.convert("Bitcoin Seed");

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
    HMac hmac = HMac(sha512digest, 64)..init(KeyParameter(hmacKey));
    Uint8List intermediate = hmac.process(seed);

    key = intermediate.sublist(0, 32);
    chainCode = intermediate.sublist(32);
    version = privateKeyVersionBytes;
    depth = 0x0;
    isPrivate = true;
    fingerprint = Uint8List.fromList([0, 0, 0, 0]);
    childNumber = Uint8List.fromList([0, 0, 0, 0]);
  }

  Key publicKey() {
    return null;
  }

  Key childKey(int pathFragment) {
    return null;
  }

  Uint8List serialize() {
    List<int> serialization = List<int>();
    serialization.addAll(version);
    serialization.add(depth);
    serialization.addAll(fingerprint);
    serialization.addAll(childNumber);
    serialization.addAll(chainCode);
    serialization.add(0); // TODO only if private!
    serialization.addAll(key);

    return Uint8List.fromList(serialization);
  }

  @override
  String toString() {
    return Base58Codec(alphabet).encode(serialize());
  }
}
