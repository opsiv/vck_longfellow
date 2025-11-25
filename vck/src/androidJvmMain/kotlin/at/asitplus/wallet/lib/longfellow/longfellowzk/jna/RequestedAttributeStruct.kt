package at.asitplus.wallet.lib.longfellow.longfellowzk.jna


import at.asitplus.wallet.lib.longfellow.longfellowzk.RequestedItem
import com.sun.jna.Structure

@Structure.FieldOrder("namespace_id", "id", "cbor_value", "namespace_len", "id_len", "cbor_value_len")
open class RequestedAttributeStruct : Structure() {
    @JvmField var namespace_id = ByteArray(64)
    @JvmField var id = ByteArray(32)
    @JvmField var cbor_value = ByteArray(64)
    @JvmField var namespace_len: Long = 0
    @JvmField var id_len: Long = 0
    @JvmField var cbor_value_len: Long = 0

    companion object {
        fun fromRequestedAttribute(requestedItem: RequestedItem) = RequestedAttributeStruct().apply {
            requestedItem.nameSpaceId.toByteArray().copyInto(namespace_id)
            namespace_len = requestedItem.nameSpaceId.length.toLong()

            requestedItem.id.toByteArray().copyInto(id)
            id_len = requestedItem.id.length.toLong()

            requestedItem.cborValue.copyInto(cbor_value)
            cbor_value_len = requestedItem.cborValue.size.toLong()

            write()
        }
    }
}

fun List<RequestedItem>.toStructArray(): Array<RequestedAttributeStruct> {
    val structs = RequestedAttributeStruct().toArray(size) as Array<RequestedAttributeStruct>
    forEachIndexed { i, requestedItem ->
        requestedItem.nameSpaceId.toByteArray().copyInto(structs[i].namespace_id)
        structs[i].namespace_len = requestedItem.nameSpaceId.length.toLong()

        requestedItem.id.toByteArray().copyInto(structs[i].id)
        structs[i].id_len = requestedItem.id.length.toLong()

        requestedItem.cborValue.copyInto(structs[i].cbor_value)
        structs[i].cbor_value_len = requestedItem.cborValue.size.toLong()

        structs[i].write()
    }
    return structs
}
