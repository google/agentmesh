import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:isolate';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:url_launcher/url_launcher.dart';

import 'sam_ffi.dart';
import 'mcp_server.dart';
import 'enroll_link.dart';
import 'scan_page.dart';
import 'oidc.dart';

// Isolate.run lives in these top-level functions, not in State methods: a closure
// there shares its context with sibling setState closures, so `this` and its
// DynamicLibrary would be sent to the isolate and rejected as unsendable.
Future<String?> _isolatedFetchControlPlaneInfo(String url) => Isolate.run(() {
  try {
    return SamNodeLib().fetchControlPlaneInfoJSON(url);
  } catch (e) {
    return jsonEncode({'error': 'FFI_ERROR: ${e.toString()}'});
  }
});

Future<String?> _isolatedEnroll(String dataDir, String controlPlaneText, String jwtText, bool allowLoopback, String labelsText, String refreshToken) => Isolate.run(() {
  try {
    return SamNodeLib().enroll(dataDir, controlPlaneText, jwtText, allowLoopback, labelsText, refreshToken);
  } catch (e) {
    return e.toString();
  }
});

Future<String?> _isolatedReEnroll(String dataDir, String labelsText) => Isolate.run(() {
  try {
    return SamNodeLib().reEnroll(dataDir, labelsText);
  } catch (e) {
    return e.toString();
  }
});

Future<String?> _isolatedEnrollBootstrap(String dataDir, String server, String token, String labelsText) => Isolate.run(() {
  try {
    return SamNodeLib().enrollBootstrap(dataDir, server, token, true, labelsText);
  } catch (e) {
    return e.toString();
  }
});

Future<String?> _isolatedUnenroll(String dataDir) => Isolate.run(() {
  try {
    return SamNodeLib().unenroll(dataDir);
  } catch (e) {
    return e.toString();
  }
});

/// Unenroll keeps the PeerID; resetIdentity deletes the key behind it too.
enum _UnenrollChoice { unenroll, resetIdentity }

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await Firebase.initializeApp();
  } catch (e) {
    debugPrint('Failed to initialize Firebase: $e');
  }
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SAM Connect',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const NodeControlPage(),
    );
  }
}

class NodeControlPage extends StatefulWidget {
  const NodeControlPage({super.key});

  @override
  State<NodeControlPage> createState() => _NodeControlPageState();
}

class _NodeControlPageState extends State<NodeControlPage> {
  // No default: a pre-filled public testnet would let a mistap enroll the
  // device somewhere the user never chose. The QR code, a pasted link or
  // the user fills it in.
  final _controlPlaneController = TextEditingController();
  final _jwtController = TextEditingController();
  // Saved by the FFI at enrollment so Re-enroll can skip the browser.
  String _refreshToken = '';
  // Bootstrap token typed or pasted by hand; a pasted sam://enroll link is
  // accepted here too and fills the URL field.
  final _joinTokenController = TextEditingController();
  bool _manualEntry = false;
  // A token-joined node cannot re-attest labels in place: /enroll re-mints
  // from the labels already on record and there is no login session to
  // refresh. Re-enroll is disabled for it; the marker dies with the data dir
  // on unenroll.
  static const _joinedWithTokenFile = 'joined-with-token';
  bool _joinedWithToken = false;
  // sam://enroll links delivered by MainActivity (stock camera app, browser).
  static const _enrollLinkChannel = MethodChannel('dev.sammesh.connect/enroll_link');
  // Bearer token for the sidecar API on 127.0.0.1:5005. Android loopback is
  // shared by every installed app, so a fixed value would let any of them
  // act as this node. Generated once and kept in the app-private data dir
  // next to the identity it protects; shown on the Config tab.
  static const _apiTokenFile = 'api-token';
  String _apiToken = '';
  bool _apiTokenVisible = false;
  // Labels are attested at enrollment; changing them requires re-enrolling.
  // The field is saved here after a successful enrollment and read back at
  // launch, like attenuation.json.
  static const _labelsFile = 'labels';
  final _labelsController = TextEditingController();

  static const _exposeChannel = MethodChannel('dev.sammesh.connect/mesh_expose');

  late SamNodeLib _samLib;
  late final String _version;
  bool?
      _isEnrolled; // null = checking, false = show enrollment, true = show dashboard
  bool _running = false;
  // Empty until something happens; the enrollment screen shows it as a card.
  String _status = '';
  String _nodeID = '';
  int _connectedPeers = 0;
  int _dhtSize = 0;
  bool _loggingIn = false;
  bool _devicePollingActive = false;
  Timer? _pollingTimer;

  // Local Services Exposure State
  bool _exposeBattery = false;
  bool _exposeLocation = false;

  // External MCP Bridging State: read when the node starts, since services
  // are declared in the start configuration.
  final _externalMcpUrlController = TextEditingController();
  final _externalMcpNameController = TextEditingController();
  final _externalMcpDescController = TextEditingController();

  // Local attenuation, one Datalog statement per line. Persisted so it
  // survives a relaunch, like the enrolled labels.
  static const _attenuationFile = 'attenuation.json';
  final _attenuationRulesController = TextEditingController();
  final _attenuationPoliciesController = TextEditingController();
  final _attenuationChecksController = TextEditingController();

  late SamDartMcpServer _embeddedMcpServer;
  bool _starting = false;
  int _selectedTab = 0; // 0 = Dashboard, 1 = Services, 2 = Config

  @override
  void initState() {
    super.initState();
    _samLib = SamNodeLib();
    _version = _samLib.getVersion();
    _checkEnrollment().then((_) => _listenForEnrollLinks());
    _embeddedMcpServer = SamDartMcpServer(
      isBatteryEnabled: () => _exposeBattery,
      isLocationEnabled: () => _exposeLocation,
    );
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _enrollLinkChannel.setMethodCallHandler(null);
    _controlPlaneController.dispose();
    _jwtController.dispose();
    _joinTokenController.dispose();
    _labelsController.dispose();
    _externalMcpUrlController.dispose();
    _externalMcpNameController.dispose();
    _externalMcpDescController.dispose();
    _attenuationRulesController.dispose();
    _attenuationPoliciesController.dispose();
    _attenuationChecksController.dispose();
    super.dispose();
  }

  Future<void> _checkEnrollment() async {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final enrolled = _samLib.isEnrolled(dataDir);
    await _loadAttenuation(dataDir);
    await _loadOrCreateApiToken(dataDir);
    final labelsFile = File('$dataDir/$_labelsFile');
    if (await labelsFile.exists()) {
      _labelsController.text = await labelsFile.readAsString();
    }
    final joinedWithToken = await File('$dataDir/$_joinedWithTokenFile').exists();
    setState(() {
      _isEnrolled = enrolled;
      _joinedWithToken = joinedWithToken;
      if (enrolled) {
        _status = 'Enrolled';
        // Try to get node ID if running (though might not be started yet)
        _nodeID = _samLib.getNodeID() ?? '';
      }
    });
  }

  List<String> _splitStatements(String text) => text
      .split('\n')
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty)
      .toList();

  Future<void> _loadAttenuation(String dataDir) async {
    final file = File('$dataDir/$_attenuationFile');
    if (!await file.exists()) return;
    try {
      final saved =
          jsonDecode(await file.readAsString()) as Map<String, dynamic>;
      String join(String key) =>
          saved[key] is List ? (saved[key] as List).join('\n') : '';
      _attenuationRulesController.text = join('rules');
      _attenuationPoliciesController.text = join('policies');
      _attenuationChecksController.text = join('checks');
    } catch (e) {
      debugPrint('DEBUG: Failed to read attenuation config: $e');
    }
  }

  Future<void> _loadOrCreateApiToken(String dataDir) async {
    final file = File('$dataDir/$_apiTokenFile');
    if (await file.exists()) {
      final saved = (await file.readAsString()).trim();
      if (saved.isNotEmpty) {
        _apiToken = saved;
        return;
      }
    }
    await _writeApiToken(file, SamDartMcpServer.newToken());
  }

  Future<void> _writeApiToken(File file, String token) async {
    await file.parent.create(recursive: true);
    await file.writeAsString(token, flush: true);
    _apiToken = token;
  }

  Future<void> _regenerateApiToken() async {
    final appDir = await getApplicationDocumentsDirectory();
    await _writeApiToken(
        File('${appDir.path}/sam_data/$_apiTokenFile'), SamDartMcpServer.newToken());
    if (mounted) setState(() {});
  }

  // The field keeps the CLI's old --labels wire format. Only the split lives
  // here; the FFI validates keys and values with the CLI's rules.
  Map<String, String> _parseLabels(String text) {
    final labels = <String, String>{};
    for (final part in text.split(',')) {
      final entry = part.trim();
      if (entry.isEmpty) continue;
      final eq = entry.indexOf('=');
      if (eq < 0) {
        throw FormatException('invalid label "$entry": expected key=value');
      }
      labels[entry.substring(0, eq).trim()] = entry.substring(eq + 1).trim();
    }
    return labels;
  }

  // Reports a malformed field through _status and returns null so the
  // caller can bail out before touching the FFI.
  Map<String, String>? _labelsOrReport(String text, String failure) {
    try {
      return _parseLabels(text);
    } on FormatException catch (e) {
      setState(() => _status = '$failure: ${e.message}');
      return null;
    }
  }

  Future<void> _saveLabels(String dataDir, String text) async {
    try {
      await Directory(dataDir).create(recursive: true);
      await File('$dataDir/$_labelsFile').writeAsString(text);
    } catch (e) {
      debugPrint('DEBUG: Failed to save labels: $e');
    }
  }

  Future<void> _saveAttenuation(
      String dataDir, Map<String, List<String>> attenuation) async {
    try {
      await Directory(dataDir).create(recursive: true);
      await File('$dataDir/$_attenuationFile')
          .writeAsString(jsonEncode(attenuation));
    } catch (e) {
      debugPrint('DEBUG: Failed to save attenuation config: $e');
    }
  }

  String _generateCodeVerifier() {
    final random = Random.secure();
    final values = List<int>.generate(32, (i) => random.nextInt(256));
    return base64UrlEncode(values).replaceAll('=', '');
  }

  // The OIDC paths need a control plane to ask for the issuer; there is no
  // default one.
  bool _requireControlPlaneUrl() {
    final server = _controlPlaneController.text.trim();
    if (isTrustedControlPlaneUrl(server)) return true;
    setState(() {
      _manualEntry = true;
      _status = server.isEmpty
          ? 'Enter the control plane URL first'
          : 'Control plane URL must be https:// (plain http only for localhost)';
    });
    return false;
  }

  String _generateCodeChallenge(String verifier) {
    final bytes = utf8.encode(verifier);
    final digest = sha256.convert(bytes);
    return base64UrlEncode(digest.bytes).replaceAll('=', '');
  }

  Future<void> _loginAndEnroll() async {
    debugPrint('DEBUG: _loginAndEnroll started');
    if (!_requireControlPlaneUrl()) return;
    setState(() {
      _loggingIn = true;
      _status = 'Fetching control plane info...';
    });

    HttpServer? server;

    try {
      final controlPlaneUrl = _controlPlaneController.text.trim();
      debugPrint('DEBUG: Fetching control plane info from $controlPlaneUrl');
      final infoJson = await _isolatedFetchControlPlaneInfo(controlPlaneUrl);
      debugPrint('DEBUG: Control plane info JSON: $infoJson');
      if (infoJson == null) {
        throw Exception('Failed to fetch control plane info');
      }

      final info = jsonDecode(infoJson);
      if (info['error'] != null) {
        throw Exception('Control plane info error: ${info['error']}');
      }

      final issuer = info['oidcIssuer'];
      final clientId = info['clientId'];
      final audience = info['audience'];

      debugPrint('DEBUG: Issuer: $issuer, ClientId: $clientId, Audience: $audience');

      if (issuer == null || clientId == null) {
        throw Exception('Incomplete control plane info received');
      }

      setState(() {
        _status = 'Discovering OIDC endpoints...';
      });

      // Simple OIDC discovery
      final discoveryUrl = '$issuer/.well-known/openid-configuration';
      debugPrint('DEBUG: Fetching OIDC config from $discoveryUrl');
      final discResponse = await http.get(Uri.parse(discoveryUrl));
      debugPrint('DEBUG: OIDC config response status: ${discResponse.statusCode}');
      if (discResponse.statusCode != 200) {
        throw Exception('Failed to discover OIDC endpoints');
      }
      final discData = jsonDecode(discResponse.body);
      final authUrl = discData['authorization_endpoint'];
      final tokenUrl = discData['token_endpoint'];

      debugPrint('DEBUG: AuthURL: $authUrl, TokenURL: $tokenUrl');

      if (authUrl == null || tokenUrl == null) {
        throw Exception('Missing endpoints in OIDC discovery');
      }

      // Start local server to capture callback
      int? selectedPort;
      for (final port in [13000, 13001, 13002]) {
        try {
          server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
          selectedPort = port;
          debugPrint('DEBUG: Bound local server to port $port (loopback)');
          break;
        } catch (e) {
          debugPrint('DEBUG: Failed to bind to port $port: $e');
        }
      }

      if (server == null || selectedPort == null) {
        throw Exception(
            'Could not bind local callback listener (ports 13000-13002 busy)');
      }

      final verifier = _generateCodeVerifier();
      final challenge = _generateCodeChallenge(verifier);
      final state = base64UrlEncode(
              List<int>.generate(16, (_) => Random.secure().nextInt(256)))
          .replaceAll('=', '');
      final redirectUri = 'http://127.0.0.1:$selectedPort/callback';

      final queryParams = {
        'response_type': 'code',
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': 'openid email profile offline_access',
        'access_type': 'offline',
        'prompt': 'consent',
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
      };
      if (audience != null && audience.isNotEmpty) {
        queryParams['audience'] = audience;
      }

      final uri = Uri.parse(authUrl).replace(queryParameters: queryParams);

      debugPrint('OIDC Login URL: $uri');
      debugPrint('Expecting callback on: $redirectUri');

      setState(() {
        _status = 'Opening browser for login...';
      });

      if (!await launchUrl(uri, mode: LaunchMode.platformDefault)) {
        throw Exception('Could not launch login URL');
      }

      debugPrint('Waiting for callback on local server...');

      String? code;
      String? receivedState;

      await for (final request in server) {
        debugPrint('DEBUG: Received request: ${request.requestedUri}');

        if (request.requestedUri.path == '/callback') {
          final query = request.requestedUri.queryParameters;
          receivedState = query['state'];
          code = query['code'];

          debugPrint('DEBUG: Callback state: $receivedState, code: $code');

          if (receivedState != state) {
            debugPrint('DEBUG: State mismatch. Expected $state, got $receivedState');
            request.response.statusCode = 400;
            request.response.write('Invalid state parameter');
            await request.response.close();
            break;
          }

          if (code == null) {
            debugPrint('DEBUG: No code in callback');
            request.response.statusCode = 400;
            request.response.write('No code received');
            await request.response.close();
            break;
          }

          request.response.headers.contentType = ContentType.html;
          request.response.write(
              '<html><body><h1>Authorization successful!</h1><p>You can close this window and return to the app.</p></body></html>');
          await request.response.close();
          debugPrint('DEBUG: Callback handled successfully');
          break; // Success
        } else {
          debugPrint(
              'DEBUG: Ignoring non-callback request: ${request.requestedUri.path}');
          request.response.statusCode = 404;
          await request.response.close();
        }
      }

      await server.close();

      if (receivedState != state) {
        throw Exception('Invalid state parameter received');
      }

      if (code == null) {
        throw Exception('No code received');
      }

      setState(() {
        _status = 'Exchanging code for token...';
      });

      final tokenResponse = await exchangeAuthorizationCode(
        tokenUrl: Uri.parse(tokenUrl),
        clientId: clientId,
        code: code,
        redirectUri: redirectUri,
        verifier: verifier,
      );

      if (tokenResponse.statusCode != 200) {
        throw Exception('Token exchange failed: ${tokenResponse.body}');
      }

      final tokenData = jsonDecode(tokenResponse.body);
      final jwt = tokenData['id_token'] ?? tokenData['access_token'];

      if (jwt == null) {
        throw Exception('No token received');
      }
      _refreshToken = tokenData['refresh_token'] ?? '';

      setState(() {
        _jwtController.text = jwt;
        _status = 'Token obtained! Enrolling...';
      });

      await _enroll();
    } catch (e) {
      setState(() {
        _status = 'Login/Enrollment failed: $e';
      });
    } finally {
      await server?.close();
      setState(() {
        _loggingIn = false;
      });
    }
  }

  Future<void> _startDeviceLogin() async {
    if (!_requireControlPlaneUrl()) return;
    setState(() {
      _loggingIn = true;
      _status = 'Fetching control plane info for device login...';
    });

    try {
      final controlPlaneUrl = _controlPlaneController.text.trim();
      debugPrint('DEBUG: Device Login: Fetching control plane info from $controlPlaneUrl');
      final infoJson = await _isolatedFetchControlPlaneInfo(controlPlaneUrl);
      if (infoJson == null) throw Exception('Failed to fetch control plane info');

      final info = jsonDecode(infoJson);
      if (info['error'] != null) {
        throw Exception('Control plane info error: ${info['error']}');
      }

      final issuer = info['oidcIssuer'];
      final clientId = info['clientId'];
      final audience = info['audience'];

      if (issuer == null || clientId == null) {
        throw Exception('Incomplete control plane info received');
      }

      // OIDC discovery
      final discoveryUrl = '$issuer/.well-known/openid-configuration';
      final discResponse = await http.get(Uri.parse(discoveryUrl));
      if (discResponse.statusCode != 200) {
        throw Exception('Failed to discover OIDC endpoints');
      }

      final discData = jsonDecode(discResponse.body);
      final deviceAuthUrl = discData['device_authorization_endpoint'];
      final tokenUrl = discData['token_endpoint'];

      if (deviceAuthUrl == null) {
        throw Exception('Device Authorization not supported by Issuer');
      }

      debugPrint('DEBUG: Device Auth Endpoint: $deviceAuthUrl');

      // 1. Request Device Code
      final deviceCodeResp = await http.post(
        Uri.parse(deviceAuthUrl),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'client_id': clientId,
          'scope': 'openid email profile offline_access',
          if (audience != null && audience.isNotEmpty) 'audience': audience,
        },
      );

      if (deviceCodeResp.statusCode != 200) {
        throw Exception('Failed to get device code: ${deviceCodeResp.body}');
      }

      final deviceData = jsonDecode(deviceCodeResp.body);
      final deviceCode = deviceData['device_code'];
      final userCode = deviceData['user_code'];
      final verificationUri = deviceData['verification_uri_complete'] ??
          deviceData['verification_uri'];
      int interval = deviceData['interval'] ?? 5; // seconds

      debugPrint('DEBUG: User Code: $userCode');
      debugPrint('DEBUG: Verification URI: $verificationUri');

      // 2. Show UI
      _devicePollingActive = true;
      _showDeviceCodeDialog(userCode, verificationUri);

      // 3. Start Polling
      _pollForDeviceToken(tokenUrl, clientId, deviceCode, interval);
    } catch (e) {
      setState(() {
        _status = 'Device Login failed: $e';
        _loggingIn = false;
      });
    }
  }

  Future<void> _pollForDeviceToken(
      String tokenUrl, String clientId, String deviceCode, int interval) async {
    debugPrint('DEBUG: Starting device token polling...');
    bool polling = true;
    while (polling && _devicePollingActive) {
      await Future.delayed(Duration(seconds: interval));

      if (!_devicePollingActive) break;

      try {
        final response = await exchangeDeviceCode(
          tokenUrl: Uri.parse(tokenUrl),
          clientId: clientId,
          deviceCode: deviceCode,
          isActive: () => mounted && _devicePollingActive,
        );
        if (response == null || !mounted || !_devicePollingActive) break;

        if (response.statusCode == 200) {
          final data = jsonDecode(response.body);
          final jwt = data['id_token'] ?? data['access_token'];
          if (jwt != null) {
            _refreshToken = data['refresh_token'] ?? '';
            setState(() {
              _jwtController.text = jwt;
              _status = 'Token obtained via Device Flow! Enrolling...';
            });
            await _enroll();
            polling = false;
            _devicePollingActive = false;
            if (mounted && Navigator.canPop(context)) {
              Navigator.pop(context);
            }
          }
        } else {
          final errorData = jsonDecode(response.body);
          final error = errorData['error'];

          if (error == 'authorization_pending') {
            debugPrint('DEBUG: Authorization pending...');
          } else if (error == 'slow_down') {
            debugPrint('DEBUG: Slow down requested');
            interval += 5; // Slow down
          } else {
            throw Exception('Device login error: $error');
          }
        }
      } catch (e) {
        debugPrint('DEBUG: Polling error: $e');
        setState(() {
          _status = 'Polling failed: $e';
        });
        polling = false;
        _devicePollingActive = false;
        if (mounted && Navigator.canPop(context)) {
          Navigator.pop(context);
        }
      }
    }

    setState(() {
      _loggingIn = false;
    });
  }

  void _showDeviceCodeDialog(String userCode, String verificationUri) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('Device Login'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('Scan this QR code or visit the URL below:'),
                const SizedBox(height: 10),
                SizedBox(
                  width: 200,
                  height: 200,
                  child: QrImageView(
                    data: verificationUri,
                    version: QrVersions.auto,
                    backgroundColor: Colors.white,
                  ),
                ),
                const SizedBox(height: 20),
                SelectableText(
                  verificationUri,
                  style: const TextStyle(
                      fontWeight: FontWeight.bold, color: Colors.blue),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 20),
                const Text('And enter this code:'),
                SelectableText(
                  userCode,
                  style: const TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 2),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () async {
                final uri = Uri.parse(verificationUri);
                if (await canLaunchUrl(uri)) {
                  await launchUrl(uri, mode: LaunchMode.externalApplication);
                }
              },
              child: const Text('Open Browser (This Device)'),
            ),
            TextButton(
              onPressed: () {
                _devicePollingActive = false;
                Navigator.of(context).pop();
                setState(() {
                  _loggingIn = false;
                  _status = 'Device login cancelled by user';
                });
              },
              child: const Text('Cancel'),
            ),
          ],
        );
      },
    );
  }

  Future<void> _enroll() async {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final controlPlaneText = _controlPlaneController.text;
    final jwtText = _jwtController.text;
    final labelsText = _labelsController.text.trim();
    final labels = _labelsOrReport(labelsText, 'Enrollment failed');
    if (labels == null) return;
    final err = await _isolatedEnroll(dataDir, controlPlaneText, jwtText, true,
        jsonEncode(labels), _refreshToken);
    if (err == null) await _saveLabels(dataDir, labelsText);

    setState(() {
      if (err != null) {
        _status = 'Enrollment failed: $err';
      } else {
        _status = 'Enrollment successful!';
        _isEnrolled = true; // Switch to Dashboard
      }
    });
  }

  // ---- Token / QR enrollment -------------------------------------------

  // Links arrive two ways: the one the activity was launched with (asked for
  // once, after the enrollment state is known) and later ones pushed while
  // the app is open.
  Future<void> _listenForEnrollLinks() async {
    _enrollLinkChannel.setMethodCallHandler((call) async {
      if (call.method == 'onLink' && call.arguments is String) {
        await _handleEnrollLink(call.arguments as String);
      }
    });
    try {
      final initial = await _enrollLinkChannel.invokeMethod<String>('getInitialLink');
      if (initial != null) await _handleEnrollLink(initial);
    } on MissingPluginException {
      // Not on Android (tests, desktop): links only come from the scanner.
    } catch (e) {
      debugPrint('DEBUG: getInitialLink failed: $e');
    }
  }

  Future<void> _scanEnrollCode() async {
    final link = await Navigator.of(context).push<EnrollLink>(
      MaterialPageRoute(builder: (_) => const ScanEnrollCodePage()),
    );
    if (link != null && mounted) await _confirmAndEnroll(link);
  }

  Future<void> _handleEnrollLink(String raw) async {
    if (!mounted) return;
    final link = parseEnrollLink(raw);
    if (link == null) {
      setState(() => _status = 'Ignored link: not a sam://enroll code');
      return;
    }
    if (_isEnrolled == true) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Already enrolled. Unenroll first to join another mesh.')));
      return;
    }
    await _confirmAndEnroll(link);
  }

  // The link came from a camera or another app: show where it leads before
  // spending the single-use token on it.
  Future<void> _confirmAndEnroll(EnrollLink link) async {
    if (!mounted) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Join this mesh?'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Control plane'),
            SelectableText(link.server,
                style: const TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            const Text('Enrollment token'),
            Text(link.tokenHint,
                style: const TextStyle(fontFamily: 'monospace')),
            const SizedBox(height: 12),
            const Text(
              'Enrollment codes admit a limited number of devices for a '
              'limited time. Labels from the Config tab are attested now.',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Join')),
        ],
      ),
    );
    if (ok == true && mounted) await _enrollWithToken(link.server, link.token);
  }

  // Manual entry: the token field takes either a bare token (with the URL
  // field naming the control plane) or a whole sam://enroll link.
  Future<void> _joinWithToken() async {
    final typed = _joinTokenController.text.trim();
    if (typed.isEmpty) {
      setState(() => _status = 'Enter an enrollment token or a sam://enroll link');
      return;
    }
    final link = parseEnrollLink(typed);
    if (link != null) {
      _controlPlaneController.text = link.server;
      await _enrollWithToken(link.server, link.token);
      return;
    }
    final server = _controlPlaneController.text.trim();
    if (!isTrustedControlPlaneUrl(server)) {
      setState(() => _status =
          'Control plane URL must be https:// (plain http only for localhost)');
      return;
    }
    await _enrollWithToken(server, typed);
  }

  Future<void> _enrollWithToken(String server, String token) async {
    final labelsText = _labelsController.text.trim();
    final labels = _labelsOrReport(labelsText, 'Enrollment failed');
    if (labels == null) return;
    setState(() {
      _loggingIn = true;
      _status = 'Enrolling with token at ${Uri.parse(server).host}...';
    });
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final err = await _isolatedEnrollBootstrap(dataDir, server, token, jsonEncode(labels));
    if (err == null) {
      await _saveLabels(dataDir, labelsText);
      try {
        await File('$dataDir/$_joinedWithTokenFile').create(recursive: true);
      } catch (e) {
        debugPrint('DEBUG: Failed to save join marker: $e');
      }
      _joinTokenController.clear();
    }
    if (!mounted) return;
    setState(() {
      _loggingIn = false;
      if (err != null) {
        _status = 'Enrollment failed: $err';
      } else {
        _controlPlaneController.text = server;
        _status = 'Enrollment successful!';
        _isEnrolled = true;
        _joinedWithToken = true;
      }
    });
  }

  // Silent path first: the refresh token saved at enrollment buys a JWT.
  // Any failure (none saved, expired, revoked) falls back to the browser.
  Future<void> _reEnroll() async {
    final labelsText = _labelsController.text.trim();
    final labels = _labelsOrReport(labelsText, 'Re-enroll failed');
    if (labels == null) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(_status)));
      return;
    }
    setState(() {
      _loggingIn = true;
      _status = 'Re-enrolling...';
    });
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final err = await _isolatedReEnroll(dataDir, jsonEncode(labels));
    if (err == null) {
      await _saveLabels(dataDir, labelsText);
      setState(() {
        _loggingIn = false;
        _status = 'Re-enrolled';
      });
    } else {
      debugPrint('DEBUG: silent re-enroll failed, using the browser: $err');
      await _loginAndEnroll();
    }
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(_status)));
  }

  void _startPolling() {
    _pollingTimer?.cancel();
    _pollingTimer = Timer.periodic(const Duration(seconds: 3), (timer) {
      if (!_running) {
        timer.cancel();
        return;
      }
      _updateMeshInfo();
    });
    _updateMeshInfo(); // Run once immediately
  }

  void _updateMeshInfo() {
    final infoJson = _samLib.getMeshInfo();
    if (infoJson != null) {
      try {
        final info = jsonDecode(infoJson);
        if (info['error'] == null) {
          if (!mounted) return;
          setState(() {
            _connectedPeers = info['connected_peers'] ?? 0;
            _dhtSize = info['dht_size'] ?? 0;
            if (info['node_id'] != null) {
              _nodeID = info['node_id'];
            }
          });
        }
      } catch (e) {
        debugPrint('DEBUG: Error parsing mesh info: $e');
      }
    }
  }

  Future<void> _start() async {
    // Backstop for the disabled button while a start is in flight.
    if (_starting) return;
    setState(() {
      _starting = true;
    });
    try {
      await _startNode();
    } finally {
      if (mounted) {
        setState(() {
          _starting = false;
        });
      }
    }
  }

  Future<void> _startNode() async {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final labels =
        _labelsOrReport(_labelsController.text.trim(), 'Start failed');
    if (labels == null) return;

    // The embedded MCP backend must be listening before the node starts:
    // services are declared in the start configuration and probed at startup,
    // there is no runtime registration.
    try {
      await _embeddedMcpServer.start();
    } catch (e) {
      setState(() {
        _status = 'Start failed: embedded MCP server: $e';
      });
      return;
    }

    final services = <Map<String, String>>[
      {
        'type': 'mcp',
        'name': 'phone-sensors',
        'description':
            'Exposes phone sensors like battery and location to the SAM mesh',
        'targetUrl': _embeddedMcpServer.targetUrl,
      },
      if (_externalMcpUrlController.text.isNotEmpty &&
          _externalMcpNameController.text.isNotEmpty)
        {
          'type': 'mcp',
          'name': _externalMcpNameController.text,
          'description': _externalMcpDescController.text,
          'targetUrl': _externalMcpUrlController.text,
        },
    ];

    final attenuation = {
      'rules': _splitStatements(_attenuationRulesController.text),
      'policies': _splitStatements(_attenuationPoliciesController.text),
      'checks': _splitStatements(_attenuationChecksController.text),
    };
    await _saveAttenuation(dataDir, attenuation);

    final err = _samLib.start({
      'dataDir': dataDir,
      'controlPlaneURL': _controlPlaneController.text,
      'meshID': 'public-mesh',
      'bindAddr': '127.0.0.1:5005', // sidecar port inside phone
      'apiToken': _apiToken,
      'allowLoopback': true,
      'enableRelay': false,
      'labels': labels,
      'services': services,
      if (attenuation.values.any((l) => l.isNotEmpty)) 'attenuation': attenuation,
    });

    if (err != null) {
      await _embeddedMcpServer.stop();
      setState(() {
        _status = 'Start failed: $err';
      });
      return;
    }

    // Start Android Foreground Service to keep process alive
    try {
      await _exposeChannel.invokeMethod('startBackgroundService');
    } catch (e) {
      debugPrint('DEBUG: Failed to start background service: $e');
      // Non-fatal, but node might be killed in background
    }

    setState(() {
      _running = true;
      _status = 'Running';
      _nodeID = _samLib.getNodeID() ?? 'unknown';
    });

    _startPolling();
  }

  void _stop() {
    _pollingTimer?.cancel();
    _embeddedMcpServer.stop();
    final err = _samLib.stop();

    // Stop Android Foreground Service
    try {
      _exposeChannel.invokeMethod('stopBackgroundService');
    } catch (e) {
      debugPrint('DEBUG: Failed to stop background service: $e');
    }

    setState(() {
      if (err != null) {
        _status = 'Stop failed: $err';
      } else {
        _running = false;
        _status = 'Stopped';
        _connectedPeers = 0;
        _dhtSize = 0;
      }
    });
  }

  Future<void> _unenroll() async {
    final choice = await showDialog<_UnenrollChoice>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unenroll Node'),
        content: const Text(
            'Unenroll disconnects this device from the mesh and deletes its '
            'credentials. The PeerID is kept, so re-enrolling brings back the '
            'same node.\n\n'
            'Reset device identity also deletes the key behind the PeerID and '
            'every local setting, so the next enrollment looks like a device '
            'the mesh has never seen.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel')),
          TextButton(
            onPressed: () =>
                Navigator.pop(context, _UnenrollChoice.resetIdentity),
            child: const Text('Reset device identity',
                style: TextStyle(color: Colors.red)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, _UnenrollChoice.unenroll),
            child: const Text('Unenroll', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (choice == null) return;

    // Closing the store here is what lets UnenrollNode take its file lock.
    if (_running) {
      _stop();
    }
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    try {
      if (choice == _UnenrollChoice.resetIdentity) {
        final dir = Directory(dataDir);
        if (await dir.exists()) {
          await dir.delete(recursive: true);
        }
      } else {
        final err = await _isolatedUnenroll(dataDir);
        if (err != null) {
          setState(() {
            _status = 'Failed to unenroll: $err';
          });
          return;
        }
      }
      setState(() {
        _isEnrolled = false;
        _joinedWithToken = false;
        _status = choice == _UnenrollChoice.resetIdentity
            ? 'Device identity reset'
            : 'Unenrolled (PeerID kept)';
        _nodeID = '';
      });
    } catch (e) {
      setState(() {
        _status = 'Failed to unenroll: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SAM Connect')),
      body: _selectedTab == 0
          ? _buildBody()
          : _selectedTab == 1
              ? _buildServicesView()
              : _buildConfigView(),
      bottomNavigationBar: _isEnrolled != null
          ? BottomNavigationBar(
              currentIndex: _selectedTab,
              onTap: (index) {
                setState(() {
                  _selectedTab = index;
                });
              },
              items: const [
                BottomNavigationBarItem(
                  icon: Icon(Icons.dashboard),
                  label: 'Dashboard',
                ),
                BottomNavigationBarItem(
                  icon: Icon(Icons.electrical_services),
                  label: 'Services',
                ),
                BottomNavigationBarItem(
                  icon: Icon(Icons.settings),
                  label: 'Config',
                ),
              ],
            )
          : null,
    );
  }

  Widget _buildBody() {
    if (_isEnrolled == null) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_isEnrolled == false) {
      return _buildEnrollmentView();
    }

    return _buildDashboardView();
  }

  Widget _buildServicesView() {
      final bool isRunning = _running;
      return SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Expose Services Section
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Expose Local Services to Mesh',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                    const SizedBox(height: 10),
                    SwitchListTile(
                      title: const Text('Battery Status'),
                      subtitle: const Text('Share battery level and charging state with mesh peers'),
                      value: _exposeBattery,
                      onChanged: (bool value) async {
                        setState(() {
                          _exposeBattery = value;
                        });
                        try {
                          await _exposeChannel.invokeMethod('setExposeBattery', {'enabled': value});
                        } catch (e) {
                          if (!mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text('Failed to toggle battery exposure: $e')),
                          );
                        }
                      },
                      secondary: const Icon(Icons.battery_std),
                    ),
                    SwitchListTile(
                      title: const Text('Location'),
                      subtitle: const Text('Share approximate location (about 1 km) with mesh peers'),
                      value: _exposeLocation,
                      onChanged: (bool value) async {
                        setState(() {
                          _exposeLocation = value;
                        });
                        try {
                          await _exposeChannel.invokeMethod('setExposeLocation', {'enabled': value});
                        } catch (e) {
                          if (!mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text('Failed to toggle location exposure: $e')),
                          );
                        }
                      },
                      secondary: const Icon(Icons.location_on),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 20),

            // External MCP Bridging Section
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Bridge External Local MCP to Mesh',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                    const SizedBox(height: 6),
                    const Text(
                      'Services are declared when the node starts. Fill these '
                      'fields before pressing Start; there is no runtime '
                      'registration.',
                      style: TextStyle(fontSize: 12, color: Colors.grey),
                    ),
                    const SizedBox(height: 10),
                    TextFormField(
                      controller: _externalMcpUrlController,
                      enabled: !isRunning,
                      inputFormatters: [
                        FilteringTextInputFormatter.deny(RegExp(r'\s'))
                      ],
                      decoration: const InputDecoration(
                        labelText: 'External MCP Server URL',
                        hintText: 'http://127.0.0.1:8080',
                        border: OutlineInputBorder(),
                      ),
                    ),
                    const SizedBox(height: 10),
                    TextFormField(
                      controller: _externalMcpNameController,
                      enabled: !isRunning,
                      decoration: const InputDecoration(
                        labelText: 'Service Name',
                        hintText: 'android-remote',
                        border: OutlineInputBorder(),
                      ),
                    ),
                    const SizedBox(height: 10),
                    TextFormField(
                      controller: _externalMcpDescController,
                      enabled: !isRunning,
                      decoration: const InputDecoration(
                        labelText: 'Description',
                        hintText: 'External Android Remote Control MCP',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      );
  }

  Widget _buildConfigView() {
    final bool isRunning = _running;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Local API Token',
                      style:
                          TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                  const SizedBox(height: 6),
                  const Text(
                    'Bearer token for the sidecar API on 127.0.0.1:5005. Any '
                    'app on this phone that holds it can act as this node, '
                    'so it is generated here and never a fixed value. '
                    'Regenerating takes effect on the next Start.',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: SelectableText(
                          _apiTokenVisible
                              ? _apiToken
                              : '\u2022' * 24,
                          style: const TextStyle(
                              fontFamily: 'monospace', fontSize: 13),
                        ),
                      ),
                      IconButton(
                        tooltip: _apiTokenVisible ? 'Hide' : 'Show',
                        icon: Icon(_apiTokenVisible
                            ? Icons.visibility_off
                            : Icons.visibility),
                        onPressed: () => setState(
                            () => _apiTokenVisible = !_apiTokenVisible),
                      ),
                      IconButton(
                        tooltip: 'Copy',
                        icon: const Icon(Icons.copy),
                        onPressed: () async {
                          await Clipboard.setData(
                              ClipboardData(text: _apiToken));
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(
                                    content: Text('Token copied')));
                          }
                        },
                      ),
                      IconButton(
                        tooltip: 'Regenerate',
                        icon: const Icon(Icons.refresh),
                        onPressed: isRunning ? null : _regenerateApiToken,
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Labels',
                      style:
                          TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                  const SizedBox(height: 6),
                  const Text(
                    'Attested by the control plane. Re-enroll re-attests '
                    'them with the saved login; the browser opens only if '
                    'that session expired. The node keeps its identity.',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const SizedBox(height: 10),
                  _buildConfigField(
                    controller: _labelsController,
                    label: 'Labels (key=value, comma-separated)',
                    hint: 'region=eu-west-1',
                    maxLines: 1,
                    enabled: !_loggingIn && !isRunning,
                  ),
                  if (_isEnrolled == true) ...[
                    const SizedBox(height: 10),
                    ElevatedButton.icon(
                      onPressed: _loggingIn || isRunning || _joinedWithToken
                          ? null
                          : _reEnroll,
                      icon: _loggingIn
                          ? const SizedBox(
                              height: 20,
                              width: 20,
                              child: CircularProgressIndicator(strokeWidth: 2))
                          : const Icon(Icons.login),
                      label: const Text('Re-enroll to apply'),
                    ),
                    if (_joinedWithToken)
                      const Padding(
                        padding: EdgeInsets.only(top: 6),
                        child: Text(
                          'Joined with a token. Unenroll and join again to change labels.',
                          style: TextStyle(fontSize: 12, color: Colors.grey),
                        ),
                      ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Limit Who May Call This Node',
                      style:
                          TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                  const SizedBox(height: 6),
                  const Text(
                    'Datalog attenuation, one statement per line. Read when '
                    'the node starts; fill these fields before pressing '
                    'Start. A syntax error fails the start.',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const SizedBox(height: 10),
                  _buildConfigField(
                    controller: _attenuationRulesController,
                    label: 'Rules',
                    hint: 'time(2026-06-30T00:00:00Z) <- true;',
                    enabled: !isRunning,
                  ),
                  const SizedBox(height: 10),
                  _buildConfigField(
                    controller: _attenuationPoliciesController,
                    label: 'Policies',
                    hint: 'deny if user("untrusted_sub_id");',
                    enabled: !isRunning,
                  ),
                  const SizedBox(height: 10),
                  _buildConfigField(
                    controller: _attenuationChecksController,
                    label: 'Checks',
                    hint: 'check if label("region", "eu-west-1");',
                    enabled: !isRunning,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            'SAM $_version',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  // Phone keyboards autocorrect and capitalise Datalog and key=value into
  // something the parser rejects.
  Widget _buildConfigField({
    required TextEditingController controller,
    required String label,
    required String hint,
    required bool enabled,
    int maxLines = 4,
  }) {
    return TextFormField(
      controller: controller,
      enabled: enabled,
      maxLines: maxLines,
      autocorrect: false,
      enableSuggestions: false,
      textCapitalization: TextCapitalization.none,
      style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        hintStyle: const TextStyle(fontFamily: 'monospace', fontSize: 13),
        alignLabelWithHint: true,
        border: const OutlineInputBorder(),
      ),
    );
  }

  // Landing screen. The primary path is the QR code a control plane prints
  // (sam-one's terminal, `sam-one token qr`); everything else sits behind
  // "Enter details manually": a bootstrap token, or the OIDC logins.
  Widget _buildEnrollmentView() {
    final busy = _loggingIn;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Welcome to SAM',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center),
          const SizedBox(height: 12),
          const Text(
            'Join a mesh by scanning the enrollment code shown by its control plane.',
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: busy ? null : _scanEnrollCode,
            icon: busy
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.qr_code_scanner),
            label: const Text('Scan enrollment code'),
            style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 18)),
          ),
          const SizedBox(height: 8),
          const Text(
            'Opening a sam://enroll link from another app works too.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
          const SizedBox(height: 16),
          TextButton.icon(
            onPressed: busy
                ? null
                : () => setState(() => _manualEntry = !_manualEntry),
            icon: Icon(_manualEntry ? Icons.expand_less : Icons.expand_more),
            label: Text(_manualEntry
                ? 'Hide manual entry'
                : 'Enter details manually'),
          ),
          if (_manualEntry) ...[
            const SizedBox(height: 8),
            TextField(
              controller: _controlPlaneController,
              enabled: !busy,
              // A pasted URL often carries a trailing space or newline.
              inputFormatters: [FilteringTextInputFormatter.deny(RegExp(r'\s'))],
              decoration: const InputDecoration(
                labelText: 'Control plane URL',
                border: OutlineInputBorder(),
                hintText: 'https://mesh.example.com',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _joinTokenController,
              enabled: !busy,
              inputFormatters: [FilteringTextInputFormatter.deny(RegExp(r'\s'))],
              onChanged: (text) {
                // A pasted sam://enroll link names the control plane itself.
                final link = parseEnrollLink(text);
                if (link != null && _controlPlaneController.text != link.server) {
                  setState(() => _controlPlaneController.text = link.server);
                }
              },
              decoration: const InputDecoration(
                labelText: 'Enrollment token',
                border: OutlineInputBorder(),
                hintText: 'sam_dev_… or a sam://enroll link',
              ),
            ),
            const SizedBox(height: 12),
            ElevatedButton.icon(
              onPressed: busy ? null : _joinWithToken,
              icon: const Icon(Icons.vpn_key),
              label: const Text('Join with token'),
              style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16)),
            ),
            const SizedBox(height: 20),
            const Row(children: [
              Expanded(child: Divider()),
              Padding(
                padding: EdgeInsets.symmetric(horizontal: 12),
                child: Text('or sign in',
                    style: TextStyle(fontSize: 12, color: Colors.grey)),
              ),
              Expanded(child: Divider()),
            ]),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: busy ? null : _loginAndEnroll,
              icon: const Icon(Icons.login),
              label: const Text('Login & Enroll (Browser)'),
              style: OutlinedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16)),
            ),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: busy ? null : _startDeviceLogin,
              icon: const Icon(Icons.tv),
              label: const Text('Device Login (TV / Other Device)'),
              style: OutlinedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16)),
            ),
          ],
          const SizedBox(height: 16),
          const Text(
            'Labels are attested at enrollment; set them on the Config tab first.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
          const SizedBox(height: 24),
          if (_status.isNotEmpty &&
              _status != 'Enrolled' &&
              _status != 'Unenrolled')
            Card(
              color: Colors.grey.shade100,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Text('Status: $_status',
                    style: const TextStyle(fontStyle: FontStyle.italic)),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildDashboardView() {
    final bool isRunning = _running;
    final Color statusColor = isRunning ? Colors.green : Colors.grey;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Status Card
          Card(
            elevation: 4,
            child: Padding(
              padding: const EdgeInsets.all(20.0),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Container(
                        width: 16,
                        height: 16,
                        decoration: BoxDecoration(
                          color: statusColor,
                          shape: BoxShape.circle,
                          boxShadow: [
                            if (isRunning)
                              BoxShadow(
                                color: Colors.green.withValues(alpha: 0.5),
                                spreadRadius: 4,
                                blurRadius: 4,
                              )
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      Text(
                        isRunning ? 'Node is Running' : 'Node is Stopped',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                          color: isRunning
                              ? Colors.green.shade700
                              : Colors.grey.shade700,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text('Mesh: public-mesh',
                      style: TextStyle(color: Colors.grey.shade600)),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),

          // Stats Grid
          Row(
            children: [
              Expanded(
                child: _buildStatCard(
                  icon: Icons.people,
                  title: 'Connected Peers',
                  value: '$_connectedPeers',
                  color: Colors.blue,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildStatCard(
                  icon: Icons.storage,
                  title: 'DHT Size',
                  value: '$_dhtSize',
                  color: Colors.purple,
                ),
              ),
            ],
          ),
          const SizedBox(height: 30),

          // Node Info
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Node ID',
                      style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  SelectableText(
                    _nodeID.isEmpty
                        ? 'Unknown (Start node to see ID)'
                        : _nodeID,
                    style:
                        const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 30),

          // Controls
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: (isRunning || _starting) ? null : _start,
                  icon: const Icon(Icons.play_arrow),
                  label: Text(_starting ? 'Starting…' : 'Start'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.green,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: isRunning ? _stop : null,
                  icon: const Icon(Icons.stop),
                  label: const Text('Stop'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.red,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Unenroll fallback
          TextButton.icon(
            onPressed: _unenroll,
            icon: const Icon(Icons.logout, color: Colors.red),
            label: const Text('Unenroll / Clear Identity',
                style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(
      {required IconData icon,
      required String title,
      required String value,
      required Color color}) {
    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Icon(icon, color: color, size: 30),
            const SizedBox(height: 10),
            Text(value,
                style:
                    const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
            const SizedBox(height: 5),
            Text(title,
                style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
