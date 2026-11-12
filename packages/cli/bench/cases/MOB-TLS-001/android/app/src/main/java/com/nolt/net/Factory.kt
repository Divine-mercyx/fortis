package com.nolt.net

fun build(): OkHttpClient = OkHttpClient.Builder()
    .sslSocketFactory(context.socketFactory, TrustAllCerts()) // @hit
    .build()

class TrustAllCerts : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {} // @hit
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
