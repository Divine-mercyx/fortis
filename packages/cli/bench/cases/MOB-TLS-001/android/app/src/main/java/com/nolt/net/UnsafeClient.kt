package com.nolt.net

object UnsafeClient {
    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {} // @hit
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    val client: OkHttpClient = OkHttpClient.Builder()
        .hostnameVerifier { _, _ -> true } // @hit
        .build()

    fun legacy() = getUnsafeOkHttpClient() // @hit
}
