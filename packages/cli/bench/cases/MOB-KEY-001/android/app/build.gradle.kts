android {
    defaultConfig {
        buildConfigField("String", "CLIENT_SECRET", "\"example-client-secret\"") // @hit
        buildConfigField("String", "API_BASE", "\"https://api.example\"")
        buildConfigField("String", "DB_PASSWORD", "\"example\"") // @hit
    }
}
