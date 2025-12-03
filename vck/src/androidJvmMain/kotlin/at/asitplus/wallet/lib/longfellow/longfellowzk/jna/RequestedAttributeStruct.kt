package at.asitplus.wallet.lib.longfellow.longfellowzk.jna


import at.asitplus.iso.ZkSignedItemSerializer
import at.asitplus.iso.ZkSignedList
import com.sun.jna.Structure

@Structure.FieldOrder("namespace_id", "id", "cbor_value", "namespace_len", "id_len", "cbor_value_len")
open class RequestedAttributeStruct : Structure() {
    @JvmField var namespace_id = ByteArray(64)
    @JvmField var id = ByteArray(32)
    @JvmField var cbor_value = ByteArray(64)
    @JvmField var namespace_len: Long = 0
    @JvmField var id_len: Long = 0
    @JvmField var cbor_value_len: Long = 0
}

@Suppress("UNCHECKED_CAST")
internal fun Map<String, ZkSignedList>.toStructArray(): Array<RequestedAttributeStruct> {
    val structs = RequestedAttributeStruct().toArray(
        values.sumOf { it.entries.size }
    ) as Array<RequestedAttributeStruct>
    val structIterator = structs.iterator()

    entries.forEach { (namespace, disclosedList) ->
        disclosedList.entries.forEach { item ->
            val struct = structIterator.next()
            val elementIdentifier = item.elementIdentifier
            val elementValue = item.elementValue

            val namespaceByteString = namespace.toByteArray()
            val elementIdentifierByteString = elementIdentifier.toByteArray()

            val elementValueCbor =  ZkSignedItemSerializer.serializeElementValue(namespace, elementValue, elementIdentifier)

            namespaceByteString.copyInto(struct.namespace_id)
            struct.namespace_len = namespaceByteString.size.toLong()
            elementIdentifierByteString.copyInto(struct.id)
            struct.id_len = elementIdentifierByteString.size.toLong()
            elementValueCbor.copyInto(struct.cbor_value)
            struct.cbor_value_len = elementValueCbor.size.toLong()

            struct.write()
        }
    }
    return structs
}