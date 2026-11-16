@Service
class WalletPinService(private val guard: WalletPinGuard) {
    fun verify(body: PinRequest): Boolean {
        guard.check(body.userId)
        return matches(body)
    }
}

@Component
class WalletPinGuard {
    fun check(key: String) {
        if (!bucket.tryConsume(1)) throw TooManyRequestsException()
    }
}
