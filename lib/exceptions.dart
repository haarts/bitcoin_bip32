class InvalidChecksum implements Exception {
  String toString() => "Checksum verification failed";
}

class KeyIsZero implements Exception {
  String toString() => "Key is zero";
}

class BiggerThanOrder implements Exception {
  String toString() => "Integer is bigger than order of curve";
}

class InvalidChildNumber implements Exception {
  String toString() => "Child number is bigger than hardened child number";
}
