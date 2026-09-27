import 'package:flutter/widgets.dart';

import 'app.dart';
import 'app_scope.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final services = await AppServices.create();
  runApp(PasswordlessApp(services: services));
}
