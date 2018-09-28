import 'dart:typed_data';
import 'dart:convert';

import 'package:convert/convert.dart';
import "package:pointycastle/api.dart";
import "package:pointycastle/macs/hmac.dart";
import "package:pointycastle/digests/sha256.dart";

final sha256digest = SHA256Digest();

/// FirstHardenedChild is the index of the firxt "harded" child key as per the
/// bip32 spec
const int FirstHardenedChild = 0x80000000;

/// PublicKeyCompressedLength is the byte count of a compressed public key
const int PublicKeyCompressedLength = 33;

/// The 4 version bytes for the private key serialization as defined in the
/// BIP21 spec
final Uint8List PrivateKeyVersionBytes = hex.decode("0488ADE4");

/// The 4 version bytes for the public key serialization as defined in the
/// BIP21 spec
final Uint8List PublicKeyVersionBytes = hex.decode("0488B21E");

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

  Key(Uint8List seed) {
    HMac hmac = HMac(sha256digest, 64)..init(KeyParameter(hmacKey));
    Uint8List intermediate = hmac.process(seed);
    print(intermediate.length);
  }
}
