import 'dart:convert';
import 'dart:typed_data';

import 'package:ethereum_util/src/typed_data.dart';

class Signer {
  static Uint8List eip712Hash(String data, String version) {
    final typedData = TypedData.fromJson(jsonDecode(data));
    return TypedDataUtils.sign(typedData, version);
  }

  static Uint8List eip712HashTypedData(TypedData typedData, String version) {
    return TypedDataUtils.sign(typedData, version);
  }
}
