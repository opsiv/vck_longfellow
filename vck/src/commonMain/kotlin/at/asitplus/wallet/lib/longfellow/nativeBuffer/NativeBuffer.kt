package at.asitplus.wallet.lib.longfellow.nativeBuffer

interface NativeBuffer {
    fun snapshot(): ByteArray
    fun free()
    val pointers: NativeBufferPointers
}