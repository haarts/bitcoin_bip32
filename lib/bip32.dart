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
import "package:pointycastle/src/utils.dart" as utils;

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
final Uint8List masterKey = utf8.encoder.convert("Bitcoin seed");

class Key {
  // 33 bytes, big endian
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
  bool get isPublic => !isPrivate;

  Key.master(Uint8List seed) {
    var keyAndChainCode = _generateKeyAndChainCode(masterKey, seed);

    key = keyAndChainCode[0];
    chainCode = keyAndChainCode[1];
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

  Key.child({this.depth});

  // NOTE I dislike that this does something when you ask the for the public key of a public key...
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

  static Uint8List publicKeyForPrivateKey(Uint8List key) {
    return ECPublicKey(
            curve.G * utils.decodeBigInt(key),
            curve)
        .Q
        .getEncoded(true);
  }

  Key childKey(int childNumber) {
    if (isPublic && childNumber >= firstHardenedChild) {
      // TODO make this a proper exception
      throw Exception('Can not create public key for hardned child');
    }

    return Key.child(
      depth: depth + 1,
    );
  }

  List<int> _serialize() {
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

  Uint8List _derivePrivateMessage(int childIndex) {
    Uint8List message = Uint8List(37);
    message[0] = 0;
    message.setAll(1, key);
    message.setAll(34, _serializeTo4bytes(childIndex));
    
    return message;
  }

  Uint8List _derivePublicMessage(int childIndex) {
    Uint8List message = Uint8List(37);
    message.setAll(0, key);
    message.setAll(34, _serializeTo4bytes(childIndex));
  }

  /// CKDpriv
  List<Uint8List> _derivePrivateKeyAndChainCode(int childIndex) {
    Uint8List message = childIndex >= firstHardenedChild ? _derivePrivateMessage(childIndex) : _derivePublicMessage(childIndex);
		Uint8List hash = hmacSha512(chainCode, message);

		// TODO iff leftSide bigger than order throw exception
		BigInt leftSide = utils.decodeBigInt(leftFrom(hash));

		// TODO iff childPrivateKey is zero throw exception
		BigInt childPrivateKey = leftSide * utils.decodeBigInt(key) % curve.n;

		Uint8List chainCode = rightFrom(hash);

		return [utils.encodeBigInt(childPrivateKey), chainCode];
  }

  // TODO iff childIndex >= firstHardenedChild throw exception
  /// CKDpub
  List<Uint8List> _derivePublicKeyAndChainCode(int childIndex) {
		Uint8List message = _derivePublicMessage(childIndex);
		Uint8List hash = hmacSha512(chainCode, message);

		// TODO iff leftSide bigger than order throw exception
		BigInt leftSide = utils.decodeBigInt(leftFrom(hash));

		Uint8List childPublicKey = (publicKeyForPrivateKey(leftFrom(hash)).Q + key.Q).getEncoded(true);

		return [childPublicKey, rightFrom(hash)];
  }

  List<Uint8List> _generateKeyAndChainCodeForChild(int childIndex) {
    Uint8List data = Uint8List(37);
    if (childIndex >= firstHardenedChild) {
      data[0] = 0;
      data.setAll(1, key);
    } else {
      if (isPrivate) {
        data.setAll(publicKeyForPrivateKey);
      }
    }


    data.setAll(_serializeTo4bytes(childIndex));

		return _generateKeyAndChainCode(key, data);
  }

	/// This function returns a list of length 64. The first half is the key, the
	/// second half is the chain code.
  List<Uint8List> _generateKeyAndChainCode(Uint8List key, Uint8List data) {
    HMac hmac = HMac(sha512digest, 128)..init(KeyParameter(key));
    Uint8List intermediate = hmac.process(data);

    return [intermediate.sublist(0,32), intermediate(32)];
  }

  Uint8List _serializeTo4bytes(int i) {
		ByteData bytes = ByteData(4);
		bytes.setInt32(0, i, Endian.big);

		return bytes.buffer.asUint8List();
	}

  @override
  String toString() {
    var payload = _serialize();
    var checksum = sha256digest
        .process(sha256digest.process(Uint8List.fromList(payload)))
        .getRange(0, 4);
    payload.addAll(checksum);
    return Base58Codec(alphabet).encode(payload);
  }
}
