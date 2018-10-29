import "package:test/test.dart";

import "package:bip32/bip32.dart";
import "package:bip32/src/crypto.dart";

void main() {
  const Map<String, dynamic> vector1 = {
    "seed": "000102030405060708090a0b0c0d0e0f",
    "chains": [
      {
        "chain": "m",
        "publicKey":
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "privateKey":
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
      },
      {
        "chain": "m/0'",
        "publicKey":
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        "privateKey":
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
      },
      {
        "chain": "m/0'/1",
        "publicKey":
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        "privateKey":
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
      },
      {
        "chain": "m/0'/1/2'",
        "publicKey":
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        "privateKey":
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
      },
      {
        "chain": "m/0'/1/2'/2",
        "publicKey":
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        "privateKey":
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
      },
      {
        "chain": "m/0'/1/2'/2/1000000000",
        "publicKey":
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        "privateKey":
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
      },
    ]
  };

  const Map<String, dynamic> vector2 = {
    "seed":
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    "chains": [
      {
        "chain": "m",
        "publicKey":
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        "privateKey":
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
      },
      {
        "chain": "m/0",
        "publicKey":
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        "privateKey":
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
      },
      {
        "chain": "m/0/2147483647'",
        "publicKey":
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        "privateKey":
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
      },
      {
        "chain": "m/0/2147483647'/1",
        "publicKey":
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        "privateKey":
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
      },
      {
        "chain": "m/0/2147483647'/1/2147483646'",
        "publicKey":
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        "privateKey":
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
      },
      {
        "chain": "m/0/2147483647'/1/2147483646'/2",
        "publicKey":
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        "privateKey":
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
      },
    ]
  };

  const Map<String, dynamic> vector3 = {
    "seed":
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    "chains": [
      {
        "chain": "m",
        "publicKey":
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        "privateKey":
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
      },
      {
        "chain": "m/0'",
        "publicKey":
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        "privateKey":
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
      },
    ]
  };

  [vector1, vector2, vector3].forEach((vector) {
    test("static vector", () {
      Chain chain = Chain.seed(vector["seed"]);
      vector["chains"].forEach((child) {
        ExtendedPrivateKey privateKey = chain.forPath(child["chain"]);
        expect(privateKey.toString(), child["privateKey"]);

        ExtendedPublicKey publicKey = privateKey.publicKey();
        expect(publicKey.toString(), child["publicKey"]);
      });
    });
  });

  group("chain", () {
    test("throw exception when generating private key based on public key", () {
      Chain chain = Chain.import(vector1["chains"][0]["publicKey"]);

      expect(() => chain.forPath("m"), throwsA(TypeMatcher<InvalidPath>()));
    });

    test("throws exception when path doesn't start with 'm' or 'M'", () {
      Chain chain = Chain.import(vector1["chains"][0]["publicKey"]);

      expect(
          () => chain.forPath("/foobar"), throwsA(TypeMatcher<InvalidPath>()));
    });

    group("path parser", () {
      Chain chain;

      setUp(() {
        chain = Chain.seed("00");
      });

      test("ignores trailing slashes", () {
        var key1 = chain.forPath("m/100");
        var key2 = chain.forPath("m/100/");

        expect(key1.toString(), key2.toString());
      });

      group("m", () {
        var key;
        setUp(() {
          key = chain.forPath('m');
        });

        test("has depth 0", () {
          expect(key.depth, 0);
        });

        test("has child number 0", () {
          expect(key.childNumber, 0);
        });

        test("is a private key", () {
          expect(key, TypeMatcher<ExtendedPrivateKey>());
        });
      });

      group("M", () {
        var key;
        setUp(() {
          key = chain.forPath('M');
        });

        test("has depth 0", () {
          expect(key.depth, 0);
        });

        test("has child number 0", () {
          expect(key.childNumber, 0);
        });

        test("is a public key", () {
          expect(key, TypeMatcher<ExtendedPublicKey>());
        });
      });

      group("m/100", () {
        var key;
        setUp(() {
          key = chain.forPath('m/100');
        });

        test("has depth 1", () {
          expect(key.depth, 1);
        });

        test("has child number 100", () {
          expect(key.childNumber, 100);
        });
      });

      group("m/100'", () {
        var key;
        setUp(() {
          key = chain.forPath("m/100'");
        });

        test("has depth 1", () {
          expect(key.depth, 1);
        });

        test("has child number 2147483648 + 100", () {
          expect(key.childNumber, firstHardenedChild + 100);
        });
      });

      group("m/100'/0", () {
        var key;
        setUp(() {
          key = chain.forPath("m/100'/0");
        });

        test("has depth 2", () {
          expect(key.depth, 2);
        });

        test("has child number 0", () {
          expect(key.childNumber, 0);
        });
      });
    });
  });

  test("refuse to generate a hardened child for a extended public key", () {
    ExtendedPublicKey parent =
        ExtendedKey.deserialize(vector2["chains"][0]["publicKey"]);

    expect(() => deriveExtendedPublicChildKey(parent, firstHardenedChild),
        throwsA(TypeMatcher<InvalidChildNumber>()));
  });

  group("(de)serialization", () {
    test("private master key", () {
      String serializedKey =
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

      expect(ExtendedKey.deserialize(serializedKey).toString(), serializedKey);
    });

    test("public master key", () {
      String serializedKey =
          "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

      expect(ExtendedKey.deserialize(serializedKey).toString(), serializedKey);
    });

    test("private child key", () {
      String serializedKey =
          "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";

      expect(ExtendedKey.deserialize(serializedKey).toString(), serializedKey);
    });

    test("public child key", () {
      String serializedKey =
          "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

      expect(ExtendedKey.deserialize(serializedKey).toString(), serializedKey);
    });

    test("broken checksum for private key", () {
      // (Capitalized a random character from the private master key)
      String serializedKey =
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3WJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

      expect(() => ExtendedKey.deserialize(serializedKey), throwsA(TypeMatcher<InvalidChecksum>()));
    });

    test("broken checksum for public key", () {
      // (Capitalized a random character from the public master key)
      String serializedKey =
          "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7uSUDFdp6W1EGMcet8";

      expect(() => ExtendedKey.deserialize(serializedKey), throwsA(TypeMatcher<ArgumentError>()));
    });
  });
}
