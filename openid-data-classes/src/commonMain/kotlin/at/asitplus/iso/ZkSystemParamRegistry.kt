package at.asitplus.iso

import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder

/**
 * Each Zk system should register serializers for its param keys to allow [ZkSystemSpec.params] to be properly
 * deserialized into a Map<String, Any>
 */
object ZkSystemParamRegistry {
    private val serializerMap = mutableMapOf<String, Map<String, KSerializer<*>>>()

    /**
     * Registers param serializers for a specific Iso mDoc ZK proof system.
     */
    fun register(systemName: String, paramSerializers: Map<String, KSerializer<*>>) {
        serializerMap[systemName]?.let { existing ->
            if (!existing.isCompatibleWith(paramSerializers)) {
                throw IllegalStateException(
                    "Conflicting param serializers for ZK system '$systemName'. " +
                    "Existing: ${existing.mapValues { it.value.descriptor.serialName }}, " +
                    "New: ${paramSerializers.mapValues {it.value.descriptor.serialName }}"
                )
            }
            serializerMap[systemName] = existing + paramSerializers
            return

        }

        serializerMap[systemName] = paramSerializers
    }

    fun lookupSerializer(systemName: String, paramKey: String): KSerializer<*>?
         = serializerMap[systemName]?.get(paramKey)


    fun encode(
        systemName: String,
        paramKey: String,
        descriptor: SerialDescriptor,
        index: Int,
        compositeEncoder: CompositeEncoder,
        value: Any,
    ) {
        lookupSerializer(systemName, paramKey)?.let { serializer ->
            @Suppress("UNCHECKED_CAST")
            compositeEncoder.encodeSerializableElement(descriptor, index, serializer as KSerializer<Any>, value)
            return
        }
        Napier.d("No serializer registered for $paramKey' with value '$value' in system '$systemName', falling back to defaults")
        when (value) {
            is String -> compositeEncoder.encodeStringElement(descriptor, index, value)
            is Int -> compositeEncoder.encodeIntElement(descriptor, index, value)
            is Long -> compositeEncoder.encodeLongElement(descriptor, index, value)
            is Boolean -> compositeEncoder.encodeBooleanElement(descriptor, index, value)
            is Double -> compositeEncoder.encodeDoubleElement(descriptor, index, value)
            else -> error("Cannot encode param '$paramKey' with value '$value'. " +
                    "System '$systemName' has no registered serializer for ${value.javaClass.canonicalName}")
        }
    }

    fun decode(
        systemName: String,
        paramKey: String,
        descriptor: SerialDescriptor,
        index: Int,
        compositeDecoder: CompositeDecoder
    ): Any? {
        lookupSerializer(systemName, paramKey)?.let { serializer ->
            @Suppress("UNCHECKED_CAST")
            return compositeDecoder.decodeSerializableElement(descriptor, index, serializer)
        }
        error("Cannot decode param '$paramKey'. System '$systemName' has no registered serializer")
        // TODO: fallbacks? String -> Int -> else?
    }


}

private fun Map<String, KSerializer<*>>.isCompatibleWith(otherSerializers: Map<String, KSerializer<*>>): Boolean =
    this.keys.intersect(otherSerializers.keys).all {this[it] == otherSerializers[it]}
