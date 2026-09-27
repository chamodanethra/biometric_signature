/// The mock server's clock, with adjustable skew for fault injection.
class Clock {
  /// Creates a clock reading [source] (defaults to the system clock, UTC).
  Clock({DateTime Function()? source})
      : _source = source ?? (() => DateTime.now().toUtc());

  final DateTime Function() _source;

  /// Added to every reading. Set it to simulate a device or server whose
  /// clock is off (e.g. to exercise a ±60 s timestamp window).
  Duration skew = Duration.zero;

  /// The current time plus [skew].
  DateTime now() => _source().add(skew);
}

/// A clock that only moves when told to. For tests.
class ManualClock extends Clock {
  /// Creates a clock starting at [start].
  ManualClock(DateTime start)
      : _now = start.toUtc(),
        super();

  DateTime _now;

  @override
  DateTime now() => _now.add(skew);

  /// Moves the clock forward.
  void advance(Duration by) => _now = _now.add(by);

  /// Sets the clock.
  set time(DateTime value) => _now = value.toUtc();
}
