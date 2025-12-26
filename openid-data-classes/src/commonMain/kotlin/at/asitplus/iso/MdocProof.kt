package at.asitplus.iso

import kotlinx.serialization.Contextual
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class MdocProof(
    @SerialName("proof")
    val proof: ByteArray,

    @SerialName("timestamp")
    val timestamp: Instant,

    @SerialName("nameSpaces")
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val namespaces: Map<String, @Contextual ZkSignedList>? = null,

    @SerialName("doctype")
    val doctype: String,

    @SerialName("zk_system")
    val zkSystem: String,

    @SerialName("circuit_hash")
    val circuitHash: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MdocProof) return false

        if (!proof.contentEquals(other.proof)) return false
        if (timestamp != other.timestamp) return false
        if (namespaces != other.namespaces) return false
        if (doctype != other.doctype) return false
        if (zkSystem != other.zkSystem) return false
        if (circuitHash != other.circuitHash) return false

        return true
    }

    override fun hashCode(): Int {
        var result = proof.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + namespaces.hashCode()
        result = 31 * result + doctype.hashCode()
        result = 31 * result + zkSystem.hashCode()
        result = 31 * result + circuitHash.hashCode()
        return result
    }
}