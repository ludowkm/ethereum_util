import 'dart:convert';
import 'dart:typed_data';

import 'package:ethereum_util/ethereum_util.dart';
import 'package:ethereum_util/src/bytes.dart';
import 'package:ethereum_util/src/keccak.dart' as keccak;
import 'package:test/test.dart';

void main() {
  test('signedTypeData', () {
    final Map<String, dynamic> rawTypedData = {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
          {"name": "name", "type": "string"},
          {"name": "wallet", "type": "address"}
        ],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person"},
          {"name": "contents", "type": "string"}
        ]
      },
      "primaryType": "Mail",
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "message": {
        "from": {
          "name": "Cow",
          "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        },
        "to": {
          "name": "Bob",
          "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
        },
        "contents": "Hello, Bob!"
      }
    };

    final typedData = TypedData.fromJson(rawTypedData);
    final privateKey = keccak.keccak256(Uint8List.fromList(utf8.encode('cow')));

    final sig = signTypedData(privateKey, MsgParams(data: typedData), 'V3');

    expect(sig,
        '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeData with bytes', () {
    final Map<String, dynamic> rawTypedData = {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
          {"name": "name", "type": "string"},
          {"name": "wallet", "type": "address"}
        ],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person"},
          {"name": "contents", "type": "string"},
          {"name": "payload", "type": "bytes"}
        ]
      },
      "primaryType": "Mail",
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "message": {
        "from": {
          "name": "Cow",
          "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        },
        "to": {
          "name": "Bob",
          "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
        },
        "contents": "Hello, Bob!",
        "payload":
            "0x25192142931f380985072cdd991e37f65cf8253ba7a0e675b54163a1d133b8ca"
      }
    };

    final typedData = TypedData.fromJson(rawTypedData);
    final privateKey = keccak.keccak256(Uint8List.fromList(utf8.encode('cow')));

    final sig = signTypedData(privateKey, MsgParams(data: typedData), 'V3');

    expect(sig,
        '0xdd17ea877a7da411c85ff94bc54180631d0e86efdcd68876aeb2e051417b68e76be6858d67b20baf7be9c6402d49930bfea2535e9ae150e85838ee265094fd081b');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeData_v4', () {
    final Map<String, dynamic> rawTypedData = {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
          {"name": "name", "type": "string"},
          {"name": "wallets", "type": "address[]"}
        ],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person[]"},
          {"name": "contents", "type": "string"}
        ],
        "Group": [
          {"name": "name", "type": "string"},
          {"name": "members", "type": "Person[]"}
        ]
      },
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "primaryType": "Mail",
      "message": {
        "from": {
          "name": "Cow",
          "wallets": [
            "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
          ]
        },
        "to": [
          {
            "name": "Bob",
            "wallets": [
              "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
              "0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57",
              "0xB0B0b0b0b0b0B000000000000000000000000000"
            ]
          }
        ],
        "contents": "Hello, Bob!"
      }
    };

    final typedData = TypedData.fromJson(rawTypedData);
    final privateKey = keccak.keccak256(Uint8List.fromList(utf8.encode('cow')));

    final sig = signTypedData(privateKey, MsgParams(data: typedData), 'V4');

    expect(sig,
        '0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f749061b');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('signedTypeMessage V4 with recursive types', () {
    final Map<String, dynamic> rawTypedData = {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
          {"name": "name", "type": "string"},
          {"name": "mother", "type": "Person"},
          {"name": "father", "type": "Person"}
        ]
      },
      "domain": {
        "name": "Family Tree",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "primaryType": "Person",
      "message": {
        "name": "Jon",
        "mother": {
          "name": "Lyanna",
          "father": {"name": "Rickard"}
        },
        "father": {
          "name": "Rhaegar",
          "father": {"name": "Aeris II"}
        }
      }
    };

    final typedData = TypedData.fromJson(rawTypedData);
    final privateKey =
        keccak.keccak256(Uint8List.fromList(utf8.encode('dragon')));

    final sig = signTypedData(privateKey, MsgParams(data: typedData), 'V4');

    expect(sig,
        '0xf2ec61e636ff7bb3ac8bc2a4cc2c8b8f635dd1b2ec8094c963128b358e79c85c5ca6dd637ed7e80f0436fe8fce39c0e5f2082c9517fe677cc2917dcd6c84ba881c');
  });
  //////////////////////////////////////////////////////////////////////////////
  test('unbound sign typed data utility functions', () {
    final Map<String, dynamic> rawTypedData = {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
          {"name": "name", "type": "string"},
          {"name": "mother", "type": "Person"},
          {"name": "father", "type": "Person"}
        ]
      },
      "domain": {
        "name": "Family Tree",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "primaryType": "Person",
      "message": {
        "name": "Jon",
        "mother": {
          "name": "Lyanna",
          "father": {"name": "Rickard"}
        },
        "father": {
          "name": "Rhaegar",
          "father": {"name": "Aeris II"}
        }
      }
    };

    final typedData = TypedData.fromJson(rawTypedData);
    expect(TypedDataUtils.encodeType('Person', typedData.types),
        'Person(string name,Person mother,Person father)');
    expect(bufferToHex(TypedDataUtils.hashType('Person', typedData.types)),
        '0x7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116');
    expect(
        bufferToHex(
          TypedDataUtils.encodeData(
              'Person', typedData.message['mother'], typedData.types, 'V4'),
        ),
        '0x${[
          '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
          'afe4142a2b3e7b0503b44951e6030e0e2c5000ef83c61857e2e6003e7aef8570',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '88f14be0dd46a8ec608ccbff6d3923a8b4e95cdfc9648f0db6d92a99a264cb36',
        ].join('')}');
    expect(
        bufferToHex(
          TypedDataUtils.hashStruct(
              'Person', typedData.message['mother'], typedData.types, 'V4'),
        ),
        '0x9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b');
    expect(
        bufferToHex(
          TypedDataUtils.encodeData(
              'Person', typedData.message['father'], typedData.types, 'V4'),
        ),
        '0x${[
          '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
          'b2a7c7faba769181e578a391a6a6811a3e84080c6a3770a0bf8a856dfa79d333',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '02cc7460f2c9ff107904cff671ec6fee57ba3dd7decf999fe9fe056f3fd4d56e',
        ].join('')}');
    expect(
        bufferToHex(
          TypedDataUtils.hashStruct(
              'Person', typedData.message['father'], typedData.types, 'V4'),
        ),
        '0xb852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8');
    expect(
        bufferToHex(
          TypedDataUtils.encodeData(
            typedData.primaryType,
            typedData.message,
            typedData.types,
            'V4',
          ),
        ),
        '0x${[
          '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
          'e8d55aa98b6b411f04dbcf9b23f29247bb0e335a6bc5368220032fdcb9e5927f',
          '9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b',
          'b852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8',
        ].join('')}');
    expect(
        bufferToHex(
          TypedDataUtils.hashStruct(
            typedData.primaryType,
            typedData.message,
            typedData.types,
            'V4',
          ),
        ),
        '0xfdc7b6d35bbd81f7fa78708604f57569a10edff2ca329c8011373f0667821a45');
    expect(
        bufferToHex(
          TypedDataUtils.hashStruct(
              'EIP712Domain', typedData.domain, typedData.types, 'V4'),
        ),
        '0xfacb2c1888f63a780c84c216bd9a81b516fc501a19bae1fc81d82df590bbdc60');
    expect(bufferToHex(Signer.eip712HashTypedData(typedData, 'V4')),
        '0x807773b9faa9879d4971b43856c4d60c2da15c6f8c062bd9d33afefb756de19c');
  });
}
