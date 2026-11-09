plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.acme.pay"
    compileSdk = 34
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.retrofit)
    implementation(libs.retrofit.gson)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.paystack)
    // Not in the catalog: written out in full.
    implementation("com.squareup.okhttp3:okhttp:4.9.0")
    implementation("com.google.code.gson:gson:$gsonVersion")
    testImplementation(libs.junit)
    androidTestImplementation(libs.espresso.core)
}
