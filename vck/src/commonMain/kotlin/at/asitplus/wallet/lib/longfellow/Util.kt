package at.asitplus.wallet.lib.longfellow

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey

internal fun CryptoPublicKey.EC.keysAsHexStrings(): Pair<String, String> {
    return "0x${publicPoint.x.toString(16)}" to "0x${publicPoint.y.toString(16)}"
}

internal inline fun <T> T?.toKmmResultIfNotNull(
    exception: () -> Throwable = { NoSuchElementException("Value was null") }
): KmmResult<T> =
    if (this != null) KmmResult.success(this) else KmmResult.failure(exception())
