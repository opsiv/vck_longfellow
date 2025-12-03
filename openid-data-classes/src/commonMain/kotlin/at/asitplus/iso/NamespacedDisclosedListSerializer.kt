package at.asitplus.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object NamespacedDisclosedListSerializer : KSerializer<Map<String, DisclosedList>> {
    private val mapSerializer = MapSerializer(String.serializer(), object :
        DisclosedListSerializer("") {})

    override val descriptor = mapSerializer.descriptor
    override fun deserialize(decoder: Decoder): Map<String, DisclosedList> = NamespacedMapEntryDeserializer().let {
        MapSerializer(it.namespaceSerializer, it.itemSerializer).deserialize(decoder)
    }

    class NamespacedMapEntryDeserializer {
        lateinit var key: String
        val namespaceSerializer = NamespaceSerializer()
        val itemSerializer = DisclosedListSerializer()

        inner class NamespaceSerializer internal constructor() : KSerializer<String> {
            override val descriptor = PrimitiveSerialDescriptor("ISO namespace", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder): String = decoder.decodeString().apply { key = this }

            override fun serialize(encoder: Encoder, value: String) {
                encoder.encodeString(value).also { key = value }
            }
        }

        inner class DisclosedListSerializer internal constructor() : KSerializer<DisclosedList> {
            override val descriptor = mapSerializer.descriptor

            override fun deserialize(decoder: Decoder): DisclosedList =
                decoder.decodeSerializableValue(DisclosedListSerializer(key))

            override fun serialize(encoder: Encoder, value: DisclosedList) =
                encoder.encodeSerializableValue(DisclosedListSerializer(key), value)
        }
    }

    override fun serialize(encoder: Encoder, value: Map<String, DisclosedList>) =
        NamespacedMapEntryDeserializer().let {
            MapSerializer(it.namespaceSerializer, it.itemSerializer).serialize(encoder, value)
        }
}
