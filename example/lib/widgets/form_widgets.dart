import 'package:examples_shared/ui.dart';
import 'package:flutter/material.dart';

import '../state/controller_base.dart';

/// Android only.
const Set<DevicePlatform> androidOnly = {DevicePlatform.android};

/// Android, iOS and macOS (not Windows).
const Set<DevicePlatform> mobileAndMac = {
  DevicePlatform.android,
  DevicePlatform.ios,
  DevicePlatform.macos,
};

/// Every supported platform.
const Set<DevicePlatform> allPlatforms = {
  DevicePlatform.android,
  DevicePlatform.ios,
  DevicePlatform.macos,
  DevicePlatform.windows,
};

/// Short label for a platform set, e.g. `Android · iOS · macOS`.
String platformSetLabel(Set<DevicePlatform> platforms) {
  if (platforms.containsAll(allPlatforms)) return 'All platforms';
  if (platforms.length == 1 && platforms.contains(DevicePlatform.android)) {
    return 'Android only';
  }
  return [
    for (final p in allPlatforms)
      if (platforms.contains(p)) p.label,
  ].join(' · ');
}

/// A pill saying which platforms honour a field; highlighted when the
/// current platform ignores it.
class PlatformTag extends StatelessWidget {
  /// Creates a tag.
  const PlatformTag({super.key, required this.platforms});

  /// Platforms that use the field.
  final Set<DevicePlatform> platforms;

  @override
  Widget build(BuildContext context) {
    final current = currentDevicePlatform();
    final applies = platforms.contains(current);
    final chip = StatusChip(
      label: platformSetLabel(platforms),
      kind: applies ? StatusKind.neutral : StatusKind.warning,
      showIcon: !applies,
      icon: Icons.block,
    );
    if (applies) return chip;
    return Tooltip(message: 'Ignored on ${current.label}', child: chip);
  }
}

/// A field name in monospace followed by its [PlatformTag].
class FieldLabel extends StatelessWidget {
  /// Creates a label.
  const FieldLabel(this.name, {super.key, this.platforms});

  /// Parameter or field name.
  final String name;

  /// Platforms that use it, if worth showing.
  final Set<DevicePlatform>? platforms;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Wrap(
      spacing: 8,
      runSpacing: 4,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        Text(
          name,
          style: monospaceStyle(context, base: theme.textTheme.titleSmall),
        ),
        if (platforms != null) PlatformTag(platforms: platforms!),
      ],
    );
  }
}

/// A switch for a boolean argument, with an explanation and platform tag.
class OptionSwitch extends StatelessWidget {
  /// Creates a switch.
  const OptionSwitch({
    super.key,
    required this.name,
    required this.value,
    required this.onChanged,
    this.description,
    this.platforms,
  });

  /// Argument name.
  final String name;

  /// Current value.
  final bool value;

  /// Called with the new value; `null` disables the switch.
  final ValueChanged<bool>? onChanged;

  /// What the option does.
  final String? description;

  /// Platforms that use it.
  final Set<DevicePlatform>? platforms;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      contentPadding: EdgeInsets.zero,
      title: FieldLabel(name, platforms: platforms),
      subtitle: description == null ? null : Text(description!),
      value: value,
      onChanged: onChanged,
    );
  }
}

/// A labelled single-choice [SegmentedButton] over enum values.
class EnumChoice<T extends Enum> extends StatelessWidget {
  /// Creates the control.
  const EnumChoice({
    super.key,
    required this.name,
    required this.values,
    required this.selected,
    required this.onChanged,
    this.labelOf,
    this.isEnabled,
    this.description,
    this.platforms,
  });

  /// Argument name.
  final String name;

  /// Values offered.
  final List<T> values;

  /// Selected value.
  final T selected;

  /// Called with the new value; `null` disables the control.
  final ValueChanged<T>? onChanged;

  /// Segment label (defaults to the enum name).
  final String Function(T value)? labelOf;

  /// Whether a value can be chosen.
  final bool Function(T value)? isEnabled;

  /// Explanation under the control.
  final String? description;

  /// Platforms that use it.
  final Set<DevicePlatform>? platforms;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          FieldLabel(name, platforms: platforms),
          const SizedBox(height: 8),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: SegmentedButton<T>(
              showSelectedIcon: false,
              segments: [
                for (final v in values)
                  ButtonSegment<T>(
                    value: v,
                    label: Text(labelOf?.call(v) ?? v.name),
                    enabled: isEnabled?.call(v) ?? true,
                  ),
              ],
              selected: {selected},
              onSelectionChanged: onChanged == null
                  ? null
                  : (s) {
                      if (s.isNotEmpty) onChanged!(s.first);
                    },
            ),
          ),
          if (description != null) ...[
            const SizedBox(height: 6),
            Text(
              description!,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ],
        ],
      ),
    );
  }
}

/// A text field for a string argument.
class ArgTextField extends StatelessWidget {
  /// Creates the field.
  const ArgTextField({
    super.key,
    required this.name,
    required this.controller,
    this.hint,
    this.helper,
    this.errorText,
    this.platforms,
    this.maxLines = 1,
    this.monospace = false,
    this.onChanged,
  });

  /// Argument name.
  final String name;

  /// Text controller.
  final TextEditingController controller;

  /// Hint when empty.
  final String? hint;

  /// Helper text.
  final String? helper;

  /// Error text.
  final String? errorText;

  /// Platforms that use it.
  final Set<DevicePlatform>? platforms;

  /// Maximum lines.
  final int maxLines;

  /// Monospace input (hex, base64).
  final bool monospace;

  /// Change callback.
  final ValueChanged<String>? onChanged;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          FieldLabel(name, platforms: platforms),
          const SizedBox(height: 6),
          TextField(
            controller: controller,
            maxLines: maxLines,
            minLines: 1,
            style: monospace ? monospaceStyle(context) : null,
            onChanged: onChanged,
            decoration: InputDecoration(
              isDense: true,
              hintText: hint ?? 'null (not set)',
              helperText: helper,
              helperMaxLines: 3,
              errorText: errorText,
              errorMaxLines: 3,
            ),
          ),
        ],
      ),
    );
  }
}

/// A button that shows progress and is disabled while [busy].
class RunButton extends StatelessWidget {
  /// Creates the button.
  const RunButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.busy = false,
    this.icon = Icons.play_arrow,
    this.tonal = false,
  });

  /// Label, usually the method name.
  final String label;

  /// Action; `null` disables the button.
  final VoidCallback? onPressed;

  /// Whether the action is running.
  final bool busy;

  /// Icon.
  final IconData icon;

  /// Use a tonal (secondary) style.
  final bool tonal;

  @override
  Widget build(BuildContext context) {
    final iconWidget = busy
        ? const SizedBox.square(
            dimension: 18,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        : Icon(icon);
    final action = busy ? null : onPressed;
    final text = Text(busy ? '$label…' : label);
    return tonal
        ? FilledButton.tonalIcon(
            onPressed: action, icon: iconWidget, label: text)
        : FilledButton.icon(onPressed: action, icon: iconWidget, label: text);
  }
}

/// A scrollable screen body with a readable maximum width.
class ScreenList extends StatelessWidget {
  /// Creates the body.
  const ScreenList({super.key, required this.children});

  /// Sections, top to bottom.
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
      child: Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 880),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              for (var i = 0; i < children.length; i++) ...[
                if (i > 0) const SizedBox(height: 16),
                children[i],
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// A short explanation at the top of a screen.
class ScreenIntro extends StatelessWidget {
  /// Creates the intro.
  const ScreenIntro(this.text, {super.key});

  /// Text.
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Text(
      text,
      style: theme.textTheme.bodyMedium
          ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
    );
  }
}

/// Shows a controller's unexpected exception, if any.
class UnexpectedErrorBanner extends StatelessWidget {
  /// Creates the banner.
  const UnexpectedErrorBanner({super.key, required this.controller});

  /// The controller.
  final ExplorerController controller;

  @override
  Widget build(BuildContext context) {
    final error = controller.unexpectedError;
    if (error == null) return const SizedBox.shrink();
    return CapabilityBanner(
      title: 'Unexpected exception',
      message: '$error\n\nThe plugin reports errors in result.code; an '
          'exception means a bug or a missing platform implementation. It is '
          'also in the call log.',
      kind: StatusKind.danger,
      action: TextButton(
        onPressed: controller.dismissUnexpectedError,
        child: const Text('Dismiss'),
      ),
    );
  }
}

/// A bulleted list of short notes.
class NoteList extends StatelessWidget {
  /// Creates the list.
  const NoteList(this.notes, {super.key});

  /// Notes.
  final List<String> notes;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final n in notes)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 2),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('•  ', style: theme.textTheme.bodyMedium),
                Expanded(child: Text(n, style: theme.textTheme.bodyMedium)),
              ],
            ),
          ),
      ],
    );
  }
}
