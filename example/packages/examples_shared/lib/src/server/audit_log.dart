import 'clock.dart';
import 'key_value_store.dart';
import 'observable.dart';

/// Severity of an [AuditEntry].
enum AuditSeverity {
  /// Routine event.
  info,

  /// A successful security-relevant action.
  success,

  /// Suspicious or degraded.
  warning,

  /// A rejected request or attack.
  danger,
}

/// One audit record.
class AuditEntry {
  /// Creates an entry.
  const AuditEntry({
    required this.time,
    required this.actor,
    required this.event,
    this.detail = '',
    this.severity = AuditSeverity.info,
  });

  /// Restores an entry from [toJson].
  factory AuditEntry.fromJson(Map<String, dynamic> json) => AuditEntry(
        time: DateTime.parse(json['time'] as String),
        actor: json['actor'] as String,
        event: json['event'] as String,
        detail: json['detail'] as String? ?? '',
        severity: AuditSeverity.values.byName(json['severity'] as String),
      );

  /// When it happened.
  final DateTime time;

  /// Who (a user id, device alias, `server` …).
  final String actor;

  /// What, e.g. `login.rejected`.
  final String event;

  /// Details.
  final String detail;

  /// Severity.
  final AuditSeverity severity;

  /// JSON form.
  Map<String, dynamic> toJson() => {
        'time': time.toIso8601String(),
        'actor': actor,
        'event': event,
        'detail': detail,
        'severity': severity.name,
      };
}

/// An append-only audit log, optionally persisted to a [KeyValueStore].
class AuditLog with Observable {
  /// Creates a log. With [store], call [load] once at startup.
  AuditLog({
    this.store,
    this.storageKey = 'audit_log',
    this.maxEntries = 500,
    Clock? clock,
  }) : clock = clock ?? Clock();

  /// Where entries are persisted, if anywhere.
  final KeyValueStore? store;

  /// Key under which entries are stored.
  final String storageKey;

  /// Oldest entries are dropped beyond this.
  final int maxEntries;

  /// Time source.
  final Clock clock;

  final List<AuditEntry> _entries = [];

  /// Entries, oldest first.
  List<AuditEntry> get entries => List.unmodifiable(_entries);

  /// Loads persisted entries.
  Future<void> load() async {
    final list = await store?.readList(storageKey);
    if (list == null) return;
    _entries
      ..clear()
      ..addAll([
        for (final e in list) AuditEntry.fromJson(e as Map<String, dynamic>),
      ]);
    notifyListeners();
  }

  /// Appends an entry.
  Future<AuditEntry> record(
    String actor,
    String event, {
    String detail = '',
    AuditSeverity severity = AuditSeverity.info,
  }) async {
    final entry = AuditEntry(
      time: clock.now(),
      actor: actor,
      event: event,
      detail: detail,
      severity: severity,
    );
    _entries.add(entry);
    if (_entries.length > maxEntries) _entries.removeAt(0);
    notifyListeners();
    await _persist();
    return entry;
  }

  /// Removes every entry.
  Future<void> clear() async {
    _entries.clear();
    notifyListeners();
    await _persist();
  }

  Future<void> _persist() async =>
      store?.write(storageKey, [for (final e in _entries) e.toJson()]);
}
