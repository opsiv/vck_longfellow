package at.asitplus.wallet.lib.longfellow

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

object AnySerializer : KSerializer<Any> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("ElementValue")

    @OptIn(ExperimentalTime::class)
    override fun serialize(encoder: Encoder, value: Any) {
        when (value) {
            is String -> encoder.encodeString(value)
            is Int -> encoder.encodeInt(value)
            is Long -> encoder.encodeLong(value)
            is Boolean -> encoder.encodeBoolean(value)
            is ByteArray -> encoder.encodeSerializableValue(ByteArraySerializer(), value)
            is LocalDate -> encoder.encodeSerializableValue(LocalDate.serializer(), value)
            is Instant -> encoder.encodeSerializableValue(InstantStringSerializer, value)
            else -> error("Unsupported type: ${value::class}")
        }
    }

    override fun deserialize(decoder: Decoder): Any {
        throw UnsupportedOperationException("Deserialization is not supported for AnySerializer")
    }
}

@OptIn(ExperimentalTime::class)
private object InstantStringSerializer: TransformingSerializerTemplate<Instant, String>(
    parent = String.serializer(),
    encodeAs = { it.toString() },
    decodeAs = { Instant.parse(it) }
)