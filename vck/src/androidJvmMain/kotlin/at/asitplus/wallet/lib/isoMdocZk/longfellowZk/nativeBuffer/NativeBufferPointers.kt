package at.asitplus.wallet.lib.isoMdocZk.longfellowZk.nativeBuffer

import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
actual class NativeBufferPointers {
    val byteArray = PointerByReference()
    val byteArrayLength = LongByReference()
}