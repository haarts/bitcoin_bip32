import 'dart:convert';
import 'package:convert/convert.dart';
import "package:bip32/bip32.dart";

void main() {
  Chain chain = Chain.seed(hex.encode(utf8.encode("some seed")));
  ExtendedPrivateKey key = chain.forPath("m/0/100");
  print(key);
}
