import 'package:flutter/material.dart';

import '../attestation/attestation_report.dart';

/// Semantic status used by the shared widgets.
enum StatusKind {
  /// Passed / healthy.
  success,

  /// Needs attention.
  warning,

  /// Failed / rejected.
  danger,

  /// Informational.
  info,

  /// No particular status.
  neutral,
}

/// Maps a check status to a [StatusKind].
StatusKind statusKindForCheck(CheckStatus status) => switch (status) {
      CheckStatus.pass => StatusKind.success,
      CheckStatus.fail => StatusKind.danger,
      CheckStatus.warn => StatusKind.warning,
      CheckStatus.info => StatusKind.info,
    };

/// Maps a trust tier to a [StatusKind].
StatusKind statusKindForTier(TrustTier tier) => switch (tier) {
      TrustTier.strongBox || TrustTier.tee => StatusKind.success,
      TrustTier.untrusted => StatusKind.danger,
      TrustTier.none => StatusKind.neutral,
    };

/// Success / warning / danger / info colours that work in light and dark
/// themes, as a [ThemeExtension].
@immutable
class StatusColors extends ThemeExtension<StatusColors> {
  /// Creates a palette.
  const StatusColors({
    required this.success,
    required this.successContainer,
    required this.onSuccessContainer,
    required this.warning,
    required this.warningContainer,
    required this.onWarningContainer,
    required this.danger,
    required this.dangerContainer,
    required this.onDangerContainer,
    required this.info,
    required this.infoContainer,
    required this.onInfoContainer,
  });

  /// Palette for light themes.
  static const StatusColors light = StatusColors(
    success: Color(0xFF1B7F3B),
    successContainer: Color(0xFFD4F4DD),
    onSuccessContainer: Color(0xFF0B3D1C),
    warning: Color(0xFF8A5A00),
    warningContainer: Color(0xFFFFE8B8),
    onWarningContainer: Color(0xFF3D2800),
    danger: Color(0xFFB3261E),
    dangerContainer: Color(0xFFF9DEDC),
    onDangerContainer: Color(0xFF410E0B),
    info: Color(0xFF0B61A4),
    infoContainer: Color(0xFFD6E8FB),
    onInfoContainer: Color(0xFF06294A),
  );

  /// Palette for dark themes.
  static const StatusColors dark = StatusColors(
    success: Color(0xFF7DDC98),
    successContainer: Color(0xFF1E4A2B),
    onSuccessContainer: Color(0xFFC8F2D4),
    warning: Color(0xFFF3C565),
    warningContainer: Color(0xFF4D3700),
    onWarningContainer: Color(0xFFFFE8B8),
    danger: Color(0xFFF2B8B5),
    dangerContainer: Color(0xFF8C1D18),
    onDangerContainer: Color(0xFFF9DEDC),
    info: Color(0xFF9CCBFB),
    infoContainer: Color(0xFF0C3D66),
    onInfoContainer: Color(0xFFD6E8FB),
  );

  /// Success accent.
  final Color success;

  /// Success background.
  final Color successContainer;

  /// Text on [successContainer].
  final Color onSuccessContainer;

  /// Warning accent.
  final Color warning;

  /// Warning background.
  final Color warningContainer;

  /// Text on [warningContainer].
  final Color onWarningContainer;

  /// Danger accent.
  final Color danger;

  /// Danger background.
  final Color dangerContainer;

  /// Text on [dangerContainer].
  final Color onDangerContainer;

  /// Info accent.
  final Color info;

  /// Info background.
  final Color infoContainer;

  /// Text on [infoContainer].
  final Color onInfoContainer;

  /// Accent colour for [kind] ([scheme] supplies the neutral one).
  Color accent(StatusKind kind, ColorScheme scheme) => switch (kind) {
        StatusKind.success => success,
        StatusKind.warning => warning,
        StatusKind.danger => danger,
        StatusKind.info => info,
        StatusKind.neutral => scheme.onSurfaceVariant,
      };

  /// Background colour for [kind].
  Color container(StatusKind kind, ColorScheme scheme) => switch (kind) {
        StatusKind.success => successContainer,
        StatusKind.warning => warningContainer,
        StatusKind.danger => dangerContainer,
        StatusKind.info => infoContainer,
        StatusKind.neutral => scheme.surfaceContainerHighest,
      };

  /// Foreground colour on [container].
  Color onContainer(StatusKind kind, ColorScheme scheme) => switch (kind) {
        StatusKind.success => onSuccessContainer,
        StatusKind.warning => onWarningContainer,
        StatusKind.danger => onDangerContainer,
        StatusKind.info => onInfoContainer,
        StatusKind.neutral => scheme.onSurface,
      };

  @override
  StatusColors copyWith({
    Color? success,
    Color? successContainer,
    Color? onSuccessContainer,
    Color? warning,
    Color? warningContainer,
    Color? onWarningContainer,
    Color? danger,
    Color? dangerContainer,
    Color? onDangerContainer,
    Color? info,
    Color? infoContainer,
    Color? onInfoContainer,
  }) =>
      StatusColors(
        success: success ?? this.success,
        successContainer: successContainer ?? this.successContainer,
        onSuccessContainer: onSuccessContainer ?? this.onSuccessContainer,
        warning: warning ?? this.warning,
        warningContainer: warningContainer ?? this.warningContainer,
        onWarningContainer: onWarningContainer ?? this.onWarningContainer,
        danger: danger ?? this.danger,
        dangerContainer: dangerContainer ?? this.dangerContainer,
        onDangerContainer: onDangerContainer ?? this.onDangerContainer,
        info: info ?? this.info,
        infoContainer: infoContainer ?? this.infoContainer,
        onInfoContainer: onInfoContainer ?? this.onInfoContainer,
      );

  @override
  StatusColors lerp(covariant ThemeExtension<StatusColors>? other, double t) {
    if (other is! StatusColors) return this;
    Color mix(Color a, Color b) => Color.lerp(a, b, t)!;
    return StatusColors(
      success: mix(success, other.success),
      successContainer: mix(successContainer, other.successContainer),
      onSuccessContainer: mix(onSuccessContainer, other.onSuccessContainer),
      warning: mix(warning, other.warning),
      warningContainer: mix(warningContainer, other.warningContainer),
      onWarningContainer: mix(onWarningContainer, other.onWarningContainer),
      danger: mix(danger, other.danger),
      dangerContainer: mix(dangerContainer, other.dangerContainer),
      onDangerContainer: mix(onDangerContainer, other.onDangerContainer),
      info: mix(info, other.info),
      infoContainer: mix(infoContainer, other.infoContainer),
      onInfoContainer: mix(onInfoContainer, other.onInfoContainer),
    );
  }
}

/// Access to [StatusColors] from a [BuildContext].
extension StatusColorsContext on BuildContext {
  /// The theme's [StatusColors], or the default for its brightness.
  StatusColors get statusColors {
    final theme = Theme.of(this);
    return theme.extension<StatusColors>() ??
        (theme.brightness == Brightness.dark
            ? StatusColors.dark
            : StatusColors.light);
  }
}

/// The shared Material 3 theme; each example app passes its own [seed].
ThemeData buildExampleTheme({
  required Color seed,
  required Brightness brightness,
}) {
  final scheme = ColorScheme.fromSeed(seedColor: seed, brightness: brightness);
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    extensions: [
      brightness == Brightness.dark ? StatusColors.dark : StatusColors.light,
    ],
    inputDecorationTheme:
        const InputDecorationTheme(border: OutlineInputBorder()),
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
  );
}

/// A monospace style derived from [base] (defaults to `bodySmall`).
TextStyle monospaceStyle(BuildContext context, {TextStyle? base}) =>
    (base ?? Theme.of(context).textTheme.bodySmall ?? const TextStyle())
        .copyWith(
      fontFamily: 'monospace',
      fontFamilyFallback: const [
        'RobotoMono',
        'Menlo',
        'Consolas',
        'Courier New',
        'Courier',
      ],
    );

/// The icon used for [kind] by the shared widgets.
IconData statusIconFor(StatusKind kind) => switch (kind) {
      StatusKind.success => Icons.check_circle,
      StatusKind.warning => Icons.warning_amber_rounded,
      StatusKind.danger => Icons.cancel,
      StatusKind.info => Icons.info_outline,
      StatusKind.neutral => Icons.circle_outlined,
    };
