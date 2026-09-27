/// Money helpers. Amounts are integer cents everywhere (in the UI, on the
/// wire and in the signed payload): canonical JSON has no floating point.
library;

/// Formats [cents] as `$1,250.00` (or `-$1,250.00`). With [signed], positive
/// amounts get a leading `+`.
String formatCents(int cents, {String currency = 'USD', bool signed = false}) {
  final negative = cents < 0;
  final abs = cents.abs();
  final digits = (abs ~/ 100).toString();
  final grouped = StringBuffer();
  for (var i = 0; i < digits.length; i++) {
    if (i > 0 && (digits.length - i) % 3 == 0) grouped.write(',');
    grouped.write(digits[i]);
  }
  final fraction = (abs % 100).toString().padLeft(2, '0');
  final symbol = currency == 'USD' ? r'$' : '$currency ';
  final sign = negative ? '-' : (signed && cents > 0 ? '+' : '');
  return '$sign$symbol$grouped.$fraction';
}

/// Parses user input such as `1250`, `1,250.5` or `$1,250.00` into cents.
///
/// Returns `null` for anything else, including more than two decimals and
/// amounts of a billion dollars or more.
int? parseAmountToCents(String input) {
  final clean = input.trim().replaceAll(',', '').replaceAll(r'$', '');
  final match = RegExp(r'^(\d{1,9})(?:\.(\d{0,2}))?$').firstMatch(clean);
  if (match == null) return null;
  final whole = int.parse(match.group(1)!);
  final fraction = (match.group(2) ?? '').padRight(2, '0');
  return whole * 100 + int.parse(fraction);
}

/// `CHK-4821` → `••4821`.
String maskAccount(String accountId) {
  final tail = accountId.length <= 4
      ? accountId
      : accountId.substring(accountId.length - 4);
  return '••$tail';
}

/// Local wall-clock time as `hh:mm:ss`.
String formatTime(DateTime time) {
  final t = time.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(t.hour)}:${two(t.minute)}:${two(t.second)}';
}

/// Local date and time as `yyyy-mm-dd hh:mm`.
String formatDateTime(DateTime time) {
  final t = time.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} '
      '${two(t.hour)}:${two(t.minute)}';
}
