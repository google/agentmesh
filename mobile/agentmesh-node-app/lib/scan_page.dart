import 'package:material_ui/material_ui.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'enroll_link.dart';

/// Full-screen camera view that pops with the first `mesh://enroll` link it
/// sees. Other codes are ignored with a hint rather than returned, so the
/// caller never has to second-guess the result.
class ScanEnrollCodePage extends StatefulWidget {
  const ScanEnrollCodePage({super.key});

  @override
  State<ScanEnrollCodePage> createState() => _ScanEnrollCodePageState();
}

class _ScanEnrollCodePageState extends State<ScanEnrollCodePage> {
  final _controller = MobileScannerController(formats: [BarcodeFormat.qrCode]);
  bool _done = false;
  String _hint = 'Point the camera at the enrollment QR code';

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_done) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw == null) continue;
      final link = parseEnrollLink(raw);
      if (link == null) {
        setState(() => _hint = 'Not an Agent Mesh enrollment code');
        continue;
      }
      _done = true;
      if (!mounted) return;
      Navigator.of(context).pop(link);
      return;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan enrollment code'),
        actions: [
          IconButton(
            icon: const Icon(Icons.flashlight_on),
            tooltip: 'Toggle torch',
            onPressed: () => _controller.toggleTorch(),
          ),
        ],
      ),
      body: Stack(
        fit: StackFit.expand,
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            errorBuilder: (context, error) => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  'Camera unavailable: ${error.errorDetails?.message ?? error.errorCode.name}\n\n'
                  'Paste the mesh://enroll link or the token instead.',
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          ),
          Align(
            alignment: Alignment.bottomCenter,
            child: Container(
              width: double.infinity,
              color: Colors.black54,
              padding: const EdgeInsets.all(16),
              child: Text(
                _hint,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
