import 'dart:io';

HttpClient insecure() {
  final client = HttpClient();
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true; // @hit
  return client;
}

HttpClient alsoInsecure() {
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) { return true; }; // @hit
  return client;
}

HttpClient strict() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => false;
  return client;
}
