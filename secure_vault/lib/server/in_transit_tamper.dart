import 'package:examples_shared/server.dart';

/// Which part of a delivered item the simulated attacker modifies.
enum TamperTarget {
  /// The bytes the device passes to `decrypt()` (a direct ciphertext or an
  /// envelope's wrapped data key). The plugin's decryption fails.
  devicePayload('the ciphertext the device decrypts'),

  /// An envelope's AES-256-GCM content. `decrypt()` still succeeds (and
  /// prompts), then the GCM tag check in Dart rejects the content.
  envelopeContent('the AES-GCM content of an envelope');

  const TamperTarget(this.label);

  /// Description.
  final String label;
}

/// A simulated attacker on the network path from the provisioning server to
/// the device.
///
/// `MockTransport.tamper` modifies *requests*; sealed items travel in a
/// *response*, so this wraps the server's route handler and flips one bit
/// after the server produced the response. The transport records the
/// modified response, so the wire log shows exactly what the device got.
class InTransitTamper with Observable {
  TamperTarget? _armed;
  String? _lastEvent;

  /// The pending fault, if any.
  TamperTarget? get armed => _armed;

  /// What the last fault did.
  String? get lastEvent => _lastEvent;

  /// Modifies the next delivery that contains a matching item.
  void arm(TamperTarget target) {
    _armed = target;
    notifyListeners();
  }

  /// Cancels the pending fault.
  void disarm() {
    _armed = null;
    notifyListeners();
  }

  /// Forgets everything.
  void reset() {
    _armed = null;
    _lastEvent = null;
    notifyListeners();
  }

  /// Wraps [handler] so an armed fault modifies its response.
  RouteHandler wrap(RouteHandler handler) => (body) async {
        final response = await handler(body);
        final target = _armed;
        final items = response['items'];
        if (target == null || items is! List) return response;
        for (final raw in items) {
          if (raw is! Map<String, dynamic>) continue;
          final field = _flip(raw, target);
          if (field != null) {
            _armed = null;
            _lastEvent = 'Flipped one bit of $field in "${raw['title']}" on '
                'its way to the device.';
            notifyListeners();
            break;
          }
        }
        return response;
      };

  static String? _flip(Map<String, dynamic> item, TamperTarget target) {
    final envelope = item['envelope'];
    switch (target) {
      case TamperTarget.devicePayload:
        if (item['ciphertext'] is String) {
          item['ciphertext'] = Tamper.flipBase64Bit(item['ciphertext']);
          return 'the ciphertext';
        }
        if (envelope is Map<String, dynamic> &&
            envelope['wrappedKey'] is String) {
          envelope['wrappedKey'] = Tamper.flipBase64Bit(envelope['wrappedKey']);
          return 'the wrapped data key';
        }
        return null;
      case TamperTarget.envelopeContent:
        if (envelope is Map<String, dynamic> &&
            envelope['ciphertext'] is String) {
          envelope['ciphertext'] = Tamper.flipBase64Bit(envelope['ciphertext']);
          return 'the envelope content';
        }
        return null;
    }
  }
}
