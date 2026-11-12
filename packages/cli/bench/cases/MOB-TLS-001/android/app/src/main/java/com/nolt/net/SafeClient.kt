package com.nolt.net

object SafeClient {
    private val pinner = CertificatePinner.Builder()
        .add("api.nolt.example", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build()

    val client: OkHttpClient = OkHttpClient.Builder().certificatePinner(pinner).build()

    // hostnameVerifier { _, _ -> true } is how the old client did it
}
