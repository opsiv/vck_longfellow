@file:Suppress("PropertyName", "FunctionName", "LocalVariableName")

package at.asitplus.wallet.lib.longfellow.longfellowzk.cinterop

import at.asitplus.signum.longfellow.longfellowzk.RequestedItem
import at.asitplus.signum.longfellow.src.iosMain.cinterop.RequestedAttribute
import kotlinx.cinterop.*
import platform.posix.memcpy

fun ResponseItem.toRequestedItem() : RequestedItem {
    val serializer = CborCredentialSerializer.lookupSerializer(responseItem.nameSpaceId, responseItem.id)
        ?: error("serializer not fouind for ${responseItem.id} in namespace ${responseItem.nameSpaceId}")

    @Suppress("UNCHECKED_CAST")
    val cborValue = coseCompliantSerializer.encodeToByteArray(
        serializer as KSerializer<Any>,
        responseItem.value
    )
    return RequestedItem(nameSpaceId, id, cborValue)
}

@OptIn(ExperimentalUnsignedTypes::class, ExperimentalForeignApi::class)
fun MemScope.convertRequestedAttributes(
    attrs: Array<RequestedItem>
): CValuesRef<RequestedAttribute>? {
    if (attrs.isEmpty()) return null

    val arr = allocArray<RequestedAttribute>(attrs.size)

    fun copyStringToNative(src: ByteArray, dstPtr: CPointer<UByteVar>): ULong {
        src.usePinned { pinned ->
            memcpy(dstPtr, pinned.addressOf(0), src.size.convert())
        }
        return src.size.toULong()
    }

    for (i in attrs.indices) {
        val src = attrs[i]
        val dst = arr[i]

        dst.namespace_len  = copyStringToNative(src.nameSpaceId.encodeToByteArray(), dst.namespace_id!!)
        dst.id_len         = copyStringToNative(src.id.encodeToByteArray(), dst.id!!)
        dst.cbor_value_len = copyStringToNative(src.cborValue, dst.cbor_value!!)
    }

    return arr
}
