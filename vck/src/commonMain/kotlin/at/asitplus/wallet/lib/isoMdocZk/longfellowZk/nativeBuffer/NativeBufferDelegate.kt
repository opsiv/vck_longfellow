package at.asitplus.wallet.lib.isoMdocZk.longfellowZk.nativeBuffer

internal expect class NativeBufferDelegate() : NativeBuffer {
    override val pointers: NativeBufferPointers
    override fun snapshot(): ByteArray
    override fun free()
}