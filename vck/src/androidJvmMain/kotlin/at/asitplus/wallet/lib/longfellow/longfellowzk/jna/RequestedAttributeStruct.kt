package at.asitplus.wallet.lib.longfellow.longfellowzk.jna


import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.ResponseItem
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.data.InstantStringSerializer
import com.sun.jna.Structure
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlin.time.Instant

@Structure.FieldOrder("namespace_id", "id", "cbor_value", "namespace_len", "id_len", "cbor_value_len")
open class RequestedAttributeStruct : Structure() {
    @JvmField var namespace_id = ByteArray(64)
    @JvmField var id = ByteArray(32)
    @JvmField var cbor_value = ByteArray(64)
    @JvmField var namespace_len: Long = 0
    @JvmField var id_len: Long = 0
    @JvmField var cbor_value_len: Long = 0
}

internal fun List<ResponseItem>.toStructArray(): Array<RequestedAttributeStruct> {
    val structs = RequestedAttributeStruct().toArray(size) as Array<RequestedAttributeStruct>
    forEachIndexed { i, responseItem ->
        responseItem.nameSpaceId.toByteArray().copyInto(structs[i].namespace_id)
        structs[i].namespace_len = responseItem.nameSpaceId.length.toLong()

        responseItem.id.toByteArray().copyInto(structs[i].id)
        structs[i].id_len = responseItem.id.length.toLong()

        val cborValue = serializeValue(
            responseItem.nameSpaceId,
            responseItem.id,
            responseItem.value
            // TODO: length checks here!
        )
        cborValue.copyInto(structs[i].cbor_value)
        structs[i].cbor_value_len = cborValue.size.toLong()

        structs[i].write()
    }
    return structs
}

private fun serializeValue(
    namespace: String,
    elementId: String,
    value: Any
): ByteArray {
    return when (value) {
        is String -> coseCompliantSerializer.encodeToByteArray(String.serializer(), value)
        is Int -> coseCompliantSerializer.encodeToByteArray(Int.serializer(), value)
        is Long -> coseCompliantSerializer.encodeToByteArray(Long.serializer(), value)
        is LocalDate -> coseCompliantSerializer.encodeToByteArray(LocalDate.serializer(), value)
        is Instant -> coseCompliantSerializer.encodeToByteArray(InstantStringSerializer(), value)
        is Boolean -> coseCompliantSerializer.encodeToByteArray(Boolean.serializer(), value)
        is ByteArray -> coseCompliantSerializer.encodeToByteArray(ByteArraySerializer(), value)
        else -> {
            val serializer = CborCredentialSerializer.lookupSerializer(namespace, elementId)
                ?: error("serializer not found for $elementId in namespace $namespace, with value $value")
            @Suppress("UNCHECKED_CAST")
            coseCompliantSerializer.encodeToByteArray(serializer as KSerializer<Any>, value)
        }
    }
}