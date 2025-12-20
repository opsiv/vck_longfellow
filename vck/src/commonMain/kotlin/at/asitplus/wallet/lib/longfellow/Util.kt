package at.asitplus.wallet.lib.longfellow

import at.asitplus.KmmResult

internal inline fun <T> T?.toKmmResultIfNotNull(
    exception: () -> Throwable = { NoSuchElementException("Value was null") }
): KmmResult<T> =
    if (this != null) KmmResult.success(this) else KmmResult.failure(exception())
