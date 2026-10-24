import Flutter
import UIKit

// iOS 27 doesn't launch an app built with its SDK unless the app adopts the
// UIScene life cycle. Flutter's own scene support (`FlutterSceneDelegate`)
// isn't available in Flutter 3.24.5, which this example also builds with, so
// the app creates its Flutter engine here and shows it from `SceneDelegate`
// below. That works on every Flutter version.
@main
@objc class AppDelegate: FlutterAppDelegate {
  /// Runs the app's Dart code; `SceneDelegate` shows it.
  lazy var flutterEngine = FlutterEngine(name: "main")

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    flutterEngine.run()
    GeneratedPluginRegistrant.register(with: flutterEngine)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  // Newer Flutter versions pick a scene configuration in FlutterAppDelegate;
  // always use this app's scene delegate instead.
  override func application(
    _ application: UIApplication,
    configurationForConnecting connectingSceneSession: UISceneSession,
    options: UIScene.ConnectionOptions
  ) -> UISceneConfiguration {
    let configuration = UISceneConfiguration(
      name: "Default Configuration",
      sessionRole: connectingSceneSession.role
    )
    configuration.delegateClass = SceneDelegate.self
    return configuration
  }
}

/// Shows the app's Flutter engine in a window.
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?

  func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options connectionOptions: UIScene.ConnectionOptions
  ) {
    guard let windowScene = scene as? UIWindowScene,
          let appDelegate = UIApplication.shared.delegate as? AppDelegate
    else { return }
    let window = UIWindow(windowScene: windowScene)
    window.rootViewController = FlutterViewController(
      engine: appDelegate.flutterEngine,
      nibName: nil,
      bundle: nil
    )
    self.window = window
    // FlutterAppDelegate finds the Flutter view controller through its window.
    appDelegate.window = window
    window.makeKeyAndVisible()
  }
}
