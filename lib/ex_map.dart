extension ExMap<K, V> on Map<dynamic, dynamic>? {
  Map<String?, String?>? toStringEntriesMap() {
    return this?.map((key, value) => MapEntry(key?.toString(), value?.toString()));
  }
}
