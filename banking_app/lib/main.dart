import 'package:flutter/material.dart';

import 'app.dart';
import 'services.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(BankingApp(services: AppServices.create()));
}
