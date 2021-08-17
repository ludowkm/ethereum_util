import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart';
import 'package:ethereum_util/ethereum_util.dart';
import 'package:ethereum_util/src/abi.dart' as ethAbi;
import 'package:ethereum_util/src/bytes.dart';
import 'package:ethereum_util/src/keccak.dart' as keccak;
import 'package:ethereum_util/src/signature.dart';
import 'package:ethereum_util/src/utils.dart';

/// Returns a continuous, hex-prefixed hex value for the signature,
/// suitable for inclusion in a JSON transaction's data field.
String concatSig(Uint8List r, Uint8List s, Uint8List v) {
  var rSig = fromSigned(r);
  var sSig = fromSigned(s);
  var vSig = bufferToInt(v);
  var rStr = _padWithZeroes(hex.encode(toUnsigned(rSig)), 64);
  var sStr = _padWithZeroes(hex.encode(toUnsigned(sSig)), 64);
  var vStr = stripHexPrefix(intToHex(vSig));
  return addHexPrefix(rStr + sStr + vStr);
}

String signTypedData(
    Uint8List privateKey, MsgParams msgParams, String version) {
  var message = TypedDataUtils.sign(msgParams.data, version);
  var sig = sign(message, privateKey);
  return concatSig(toBuffer(sig.r), toBuffer(sig.s), toBuffer(sig.v));
}

/// Return address of a signer that did signTypedData.
/// Expects the same data that were used for signing. sig is a prefixed signature.
String? recoverTypedSignature(MsgParams msgParams) {
  var publicKey = msgParams.recoverPublicKey();
  if (publicKey == null) return null;
  var sender = publicKeyToAddress(publicKey);
  return bufferToHex(sender);
}

String _padWithZeroes(String number, int length) {
  var myString = '' + number;
  while (myString.length < length) {
    myString = '0' + myString;
  }
  return myString;
}

String? normalize(dynamic input) {
  if (input == null) {
    return null;
  }

  if (!(input is String) && !(input is int)) {
    throw ArgumentError("input must be String or int");
  }

  if (input is int) {
    var buffer = toBuffer(input);
    input = bufferToHex(buffer);
  }

  return addHexPrefix(input.toLowerCase());
}

class MsgParams {
  TypedData data;
  String? sig;

  MsgParams({required this.data, this.sig});

  Uint8List? recoverPublicKey() {
    if (sig == null) return null;
    var sigParams = fromRpcSig(sig!);
    return recoverPublicKeyFromSignature(
        ECDSASignature(sigParams.r, sigParams.s, sigParams.v),
        TypedDataUtils.sign(data, 'V1'));
  }
}

class TypedData {
  Map<String, List<TypedDataField>> types;
  String primaryType;
  EIP712Domain? domain;
  Map<String, dynamic> message;

  TypedData(
      {required this.types,
      required this.primaryType,
      required this.domain,
      required this.message});

  factory TypedData.fromJson(Map<String, dynamic> json) => TypedData(
      types: (json['types'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            (e as List)
                .map((e) => TypedDataField.fromJson(e as Map<String, dynamic>))
                .toList()),
      ),
      primaryType: json['primaryType'] as String,
      domain: json['domain'] == null
          ? null
          : EIP712Domain.fromJson(json['domain'] as Map<String, dynamic>),
      message: json['message'] as Map<String, dynamic>);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'types': types,
        'primaryType': primaryType,
        'domain': domain,
        'message': message
      };
}

class TypedDataField {
  String name;
  String type;

  TypedDataField({required this.name, required this.type});

  factory TypedDataField.fromJson(Map<String, dynamic> json) => TypedDataField(
      name: json['name'] as String, type: json['type'] as String);

  Map<String, dynamic> toJson() =>
      <String, dynamic>{'name': name, 'type': type};
}

class EIP712Domain {
  String? name;
  String? version;
  int? chainId;
  String? verifyingContract;

  EIP712Domain(
      {required this.name,
      required this.version,
      required this.chainId,
      required this.verifyingContract});

  dynamic operator [](String key) {
    switch (key) {
      case 'name':
        return name;
      case 'version':
        return version;
      case 'chainId':
        return chainId;
      case 'verifyingContract':
        return verifyingContract;
      default:
        throw ArgumentError("Key ${key} is invalid");
    }
  }

  factory EIP712Domain.fromJson(Map<String, dynamic> json) => EIP712Domain(
      name: json['name'] as String,
      version: json['version'] as String,
      chainId: json['chainId'] as int,
      verifyingContract: json['verifyingContract'] as String);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'name': name,
        'version': version,
        'chainId': chainId,
        'verifyingContract': verifyingContract
      };
}

class TypedDataUtils {
  static Uint8List sign(TypedData typedData, String version) {
    var parts = BytesBuffer();
    parts.add(hex.decode('1901'));
    parts.add(
        hashStruct('EIP712Domain', typedData.domain, typedData.types, version));
    if (typedData.primaryType != 'EIP712Domain') {
      parts.add(hashStruct(
          typedData.primaryType, typedData.message, typedData.types, version));
    }
    return keccak.keccak256(parts.toBytes());
  }

  static Uint8List hashStruct(String primaryType, dynamic data,
      Map<String, List<TypedDataField>> types, String version) {
    return keccak.keccak256(encodeData(primaryType, data, types, version));
  }

  /// Hashes the type of an object
  static Uint8List hashType(String primaryType, dynamic types) {
    return keccak.keccak256(
        Uint8List.fromList(utf8.encode(encodeType(primaryType, types))));
  }

  static Uint8List encodeData(String primaryType, dynamic data,
      Map<String, List<TypedDataField>> types, String version) {
    if (!(data is Map<String, dynamic>) && !(data is EIP712Domain)) {
      throw ArgumentError("Unsupported data type");
    }

    final encodedTypes = <String>['bytes32'];
    List<dynamic> encodedValues = [];
    encodedValues.add(hashType(primaryType, types));

    if (version == 'V4') {
      List<dynamic> encodeField(String name, String type, dynamic value) {
        if (types[type] != null) {
          return [
            'bytes32',
            value == null // eslint-disable-line no-eq-null
                ? '0x0000000000000000000000000000000000000000000000000000000000000000'
                : keccak.keccak256((encodeData(type, value, types, version))),
          ];
        }

        if (value == null) {
          throw ArgumentError(
              'missing value for field ${name} of type ${type}');
        }

        if (type == 'bytes') {
          return ['bytes32', keccak.keccak256(value)];
        }

        if (type == 'string') {
          // convert string to buffer - prevents ethUtil from interpreting strings like '0xabcd' as hex
          if (value is String) {
            value = Uint8List.fromList(utf8.encode(value));
          }
          return ['bytes32', keccak.keccak256(value)];
        }

        if (type.lastIndexOf(']') == type.length - 1) {
          final parsedType = type.substring(0, type.lastIndexOf('['));
          final typeValuePairs = value
              .map(
                (item) => encodeField(name, parsedType, item),
              )
              .toList();

          final List<String> tList =
              (typeValuePairs as List).map((l) => l[0].toString()).toList();
          final List<dynamic> vList = typeValuePairs.map((l) => l[1]).toList();
          return [
            'bytes32',
            keccak.keccak256(
              ethAbi.rawEncode(
                tList,
                vList,
              ),
            ),
          ];
        }

        return [type, value];
      }

      final fields = types[primaryType];
      fields?.forEach((field) {
        final List<dynamic> result = encodeField(
          field.name,
          field.type,
          data[field.name],
        );
        encodedTypes.add(result[0]);
        encodedValues.add(result[1]);
      });
    } else {
      types[primaryType]?.forEach((TypedDataField field) {
        var value = data[field.name];
        if (value != null) {
          if (field.type == 'bytes') {
            encodedTypes.add('bytes32');
            if (value is String) {
              if (isHexPrefixed(value)) {
                value = keccak.keccak256(hexToBytes(value));
              } else {
                value = keccak.keccak256(Uint8List.fromList(utf8.encode(value)));
              }
            }
            encodedValues.add(value);
          } else if (field.type == 'string') {
            encodedTypes.add('bytes32');
            // convert string to buffer - prevents ethUtil from interpreting strings like '0xabcd' as hex
            if (value is String) {
              value = Uint8List.fromList(utf8.encode(value));
            }
            value = keccak.keccak256(value);
            encodedValues.add(value);
          } else if (types[field.type] != null) {
            encodedTypes.add('bytes32');
            value =
                keccak.keccak256(encodeData(field.type, value, types, version));
            encodedValues.add(value);
          } else if (field.type.lastIndexOf(']') == field.type.length - 1) {
            throw new ArgumentError(
                'Arrays are unimplemented in encodeData; use V4 extension');
          } else {
            encodedTypes.add(field.type);
            encodedValues.add(value);
          }
        }
      });
    }

    return ethAbi.rawEncode(encodedTypes, encodedValues);
  }

  /// Encodes the type of an object by encoding a comma delimited list of its members
  static String encodeType(
      String primaryType, Map<String, List<TypedDataField>> types) {
    var result = '';
    var deps = findTypeDependencies(primaryType, types);
    deps = deps.where((dep) => dep != primaryType).toList();
    deps.sort();
    deps.insert(0, primaryType);
    deps.forEach((dep) {
      if (!types.containsKey(dep)) {
        throw new ArgumentError('No type definition specified: ' + dep);
      }
      result += dep +
          '(' +
          types[dep]!.map((field) => field.type + ' ' + field.name).join(',') +
          ')';
    });
    return result;
  }

  /**
   * Finds all types within a type defintion object
   *
   * @param {string} primaryType - Root type
   * @param {Object} types - Type definitions
   * @param {Array} results - current set of accumulated types
   * @returns {Array} - Set of all types found in the type definition
   */
  static List<String> findTypeDependencies(
      String primaryType, Map<String, List<TypedDataField>> types,
      {List<String>? results}) {
    if (results == null) {
      results = [];
    }
    if (results.contains(primaryType) || !types.containsKey(primaryType)) {
      return results;
    }
    results.add(primaryType);
    types[primaryType]?.forEach((TypedDataField field) {
      findTypeDependencies(field.type, types, results: results).forEach((dep) {
        if (!results!.contains(dep)) {
          results.add(dep);
        }
      });
    });
    return results;
  }
}
