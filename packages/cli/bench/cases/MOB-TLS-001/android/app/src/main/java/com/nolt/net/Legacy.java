package com.nolt.net;

public class Legacy implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) { }
    public void checkServerTrusted(X509Certificate[] chain, String authType) { } // @hit
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

    static void install() {
        HttpsURLConnection.setDefaultHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER); // @hit
    }

    static class AnyHost implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) { return true; } // @hit
    }

    static Object apache() { return new NoopHostnameVerifier(); } // @hit
}
