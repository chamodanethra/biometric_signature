import 'package:flutter/material.dart';

import '../state/explorer_state.dart';
import '../state/key_alias.dart';
import 'form_widgets.dart';

/// Chips for the known aliases plus the probe alias. The selection is
/// shared by the Keys, Sign and Decrypt screens.
class AliasPicker extends StatelessWidget {
  /// Creates the picker.
  const AliasPicker({super.key, this.showProbeField = true});

  /// Whether to show the probe alias text field under the chips.
  final bool showProbeField;

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    final theme = Theme.of(context);
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const FieldLabel('keyAlias', platforms: allPlatforms),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final alias in state.aliasOptions)
                ChoiceChip(
                  key: ValueKey('alias.${alias.label}'),
                  label: Text(alias.label),
                  avatar: state.recordFor(alias) == null
                      ? null
                      : const Icon(Icons.key, size: 16),
                  tooltip: state.recordFor(alias) == null
                      ? null
                      : 'Created in this session',
                  selected: state.selectedAlias == alias,
                  onSelected: (_) => state.selectAlias(alias),
                ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            state.selectedAlias.isDefault
                ? 'keyAlias: null uses the plugin\'s default alias.'
                : 'keyAlias: \'${state.selectedAlias.value}\'. The plugin '
                    'cannot list aliases, so the Explorer tracks a fixed '
                    'set plus one custom alias.',
            style: theme.textTheme.bodySmall
                ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
          if (showProbeField) ...[
            const SizedBox(height: 8),
            const ProbeAliasField(),
          ],
        ],
      ),
    );
  }
}

/// Text field for the free-text probe alias.
class ProbeAliasField extends StatelessWidget {
  /// Creates the field.
  const ProbeAliasField({super.key});

  @override
  Widget build(BuildContext context) {
    final state = ExplorerScope.of(context);
    return ListenableBuilder(
      listenable: state,
      builder: (context, _) => TextField(
        key: const ValueKey('alias.probe'),
        controller: state.probeAliasText,
        autocorrect: false,
        decoration: InputDecoration(
          isDense: true,
          labelText: 'Custom alias',
          hintText: 'e.g. my_key-1',
          helperText: 'Adds a chip for any alias made of a–z, 0–9, _ and -',
          helperMaxLines: 2,
          errorText: state.probeAliasError,
          prefixIcon: const Icon(Icons.search),
        ),
      ),
    );
  }
}

/// Human label for [alias] in sentences.
String aliasPhrase(KeyAlias alias) =>
    alias.isDefault ? 'the default alias' : "'${alias.value}'";
