/// Thrown when deserializing a key with an invalid checksum.
///
/// The serialization contains a checksum, if the calculated checksum doesn't
/// match the stored checksum this exception is thrown.
class InvalidChecksum implements Exception {
  String toString() => "Checksum verification failed";
}

/// Thrown when a derived private key is zero.
///
/// Retry with an other child number.
class KeyZero implements Exception {
  String toString() => "Key is zero";
}

/// Thrown when a derived key is bigger than the order of the curve.
///
/// Retry with an other child number.
class KeyBiggerThanOrder implements Exception {
  String toString() => "Integer is bigger than order of curve";
}

/// Thrown when trying to derive a public key with a hardened child number.
class InvalidChildNumber implements Exception {
  String toString() => "Child number is bigger than hardened child number";
}

/// Thrown when a derived public key is infinite.
///
/// Retry with an other child number.
class KeyInfinite implements Exception {
  String toString() => "ECPoint is infinite";
}

/// Thrown when trying to derive a child key with a wrong path.
class InvalidPath implements Exception {
  String message;
  InvalidPath(this.message);

  String toString() => message;
}

/// Thrown when deserializing a key which is not of correct length.
class InvalidKeyLength implements Exception {
  int actual;
  int expected;

  InvalidKeyLength(this.actual, this.expected);

  String toString() =>
      "Key length not correct. Should be $expected, is $actual";
}
