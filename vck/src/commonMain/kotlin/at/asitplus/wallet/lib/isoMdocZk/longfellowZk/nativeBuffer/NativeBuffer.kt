package at.asitplus.wallet.lib.isoMdocZk.longfellowZk.nativeBuffer

interface NativeBuffer {
    fun snapshot(): ByteArray
    fun free()
    val pointers: NativeBufferPointers
}