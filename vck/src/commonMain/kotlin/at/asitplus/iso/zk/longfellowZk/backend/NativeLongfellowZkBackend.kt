package at.asitplus.iso.zk.longfellowZk.backend

import at.asitplus.KmmResult

expect object NativeLongfellowZkBackend: LongfellowZkBackend


internal inline fun <T> T?.toKmmResultIfNotNull(
    exception: () -> Throwable = { NoSuchElementException("Value was null") }
): KmmResult<T> =
    if (this != null) KmmResult.success(this) else KmmResult.failure(exception())

