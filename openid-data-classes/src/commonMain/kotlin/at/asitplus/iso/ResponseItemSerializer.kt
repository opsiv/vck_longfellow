package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import io.github.aakira.napier.Napier
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlin.time.Instant

object  ResponseItemSerializer :
    KSerializer<ResponseItem> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ResponseItem") {
            element(ResponseItem.PROP_NAMESPACE_ID, String.serializer().descriptor)
            element(ResponseItem.PROP_ID, String.serializer().descriptor)
            element(ResponseItem.PROP_VALUE, String.serializer().descriptor)
        }

    override fun serialize(encoder: Encoder, value: ResponseItem) {
        encoder.encodeStructure(descriptor) {
            encodeStringElement(descriptor, 0, value.nameSpaceId)
            encodeStringElement(descriptor, 1, value.id)
            encodeAnything(value, 2)
        }
    }

    private fun CompositeEncoder.encodeAnything(value: ResponseItem, index: Int) {
        val elementValueSerializer = buildElementValueSerializer(value.nameSpaceId, value.id, value.value)
        val descriptor = buildClassSerialDescriptor("IssuerSignedItem") {
            element(ResponseItem.PROP_NAMESPACE_ID, String.serializer().descriptor)
            element(ResponseItem.PROP_ID, String.serializer().descriptor)
            element(ResponseItem.PROP_VALUE, elementValueSerializer.descriptor, value.value.annotations())
        }

        when (val it = value.value) {
            is String -> encodeStringElement(descriptor, index, it)
            is Int -> encodeIntElement(descriptor, index, it)
            is Long -> encodeLongElement(descriptor, index, it)
            is LocalDate -> encodeSerializableElement(descriptor, index, LocalDate.serializer(), it)
            is Instant -> encodeSerializableElement(descriptor, index, InstantStringSerializer, it)
            is Boolean -> encodeBooleanElement(descriptor, index, it)
            is ByteArray -> encodeSerializableElement(descriptor, index, ByteArraySerializer(), it)
            else -> CborCredentialSerializer.encode(value.nameSpaceId, value.id, descriptor, index, this, it)
        }
    }

    /**
     * Tags date time elements correctly,
     * see [RFC 8949 3.4.1](https://datatracker.ietf.org/doc/html/rfc8949#name-standard-date-time-string) for [Instant]
     * (or "date-time"), see [RFC 8943](https://datatracker.ietf.org/doc/html/rfc8943) for [LocalDate] (or "full-date")
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    private fun Any.annotations() =
        when (this) {
            is LocalDate -> listOf(ValueTags(1004uL))
            is Instant -> listOf(ValueTags(0uL))
            else -> emptyList()
        }

    private inline fun <reified T> buildElementValueSerializer(
        namespace: String,
        elementIdentifier: String,
        elementValue: T
    ) = when (elementValue) {
        is String -> String.serializer()
        is Int -> Int.serializer()
        is Long -> Long.serializer()
        is LocalDate -> LocalDate.serializer()
        is Instant -> InstantStringSerializer
        is Boolean -> Boolean.serializer()
        is ByteArray -> ByteArraySerializer()
        is Any -> CborCredentialSerializer.lookupSerializer(namespace, elementIdentifier)
            ?: error("serializer not found for $elementIdentifier, with value $elementValue")

        else -> error("serializer not found for $elementIdentifier, with value $elementValue")
    }

    override fun deserialize(decoder: Decoder): ResponseItem {
        var nameSpaceId: String? = null
        var id: String? = null
        var value: Any? = null

        decoder.decodeStructure(descriptor) {
            while (true) {
                val name = decodeStringElement(descriptor, 0)
                val index = descriptor.getElementIndex(name)
                when (name) {
                    ResponseItem.PROP_NAMESPACE_ID -> nameSpaceId = decodeStringElement(descriptor, index)
                    ResponseItem.PROP_ID -> id = decodeStringElement(descriptor, index) // TODO: compare with what IssuerSignedItemSerializer (and DeviceSignedItemListSerializer) does
                    ResponseItem.PROP_VALUE -> value = decodeAnything(index, id, nameSpaceId)
                }
                if (nameSpaceId != null && id != null && value != null) break
            }
        }
        return ResponseItem(
            nameSpaceId = nameSpaceId!!,
            id = id!!,
            value = value!!,
        )
    }

    private fun CompositeDecoder.decodeAnything(index: Int, elementIdentifier: String?, namespace: String?): Any {
        if (elementIdentifier != null && namespace != null) {
            CborCredentialSerializer.decode(descriptor, index, this, elementIdentifier, namespace)
                ?.let { return it }
        }

        catchingUnwrapped { return decodeStringElement(descriptor, index) }
        catchingUnwrapped { return decodeLongElement(descriptor, index) }
        catchingUnwrapped { return decodeDoubleElement(descriptor, index) }
        catchingUnwrapped { return decodeBooleanElement(descriptor, index) }

        throw IllegalArgumentException("Could not decode value at $index")
    }
}