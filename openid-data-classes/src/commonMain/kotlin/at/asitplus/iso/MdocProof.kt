package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class MdocProof(
    @SerialName("proof")
    val proof: ByteArray,

    @SerialName("timestamp")
    val timestamp: Instant,

    @SerialName("attributes")
    val attributes: List<ResponseItem>,

    @SerialName("doctype")
    val doctype: String,

    // TODO: what about the circuit that is in use? it should be specified _somewhere_
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MdocProof

        if (!proof.contentEquals(other.proof)) return false
        if (timestamp != other.timestamp) return false
        if (attributes != other.attributes) return false
        if (doctype != other.doctype) return false

        return true
    }

    override fun hashCode(): Int {
        var result = proof.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + attributes.hashCode()
        result = 31 * result + doctype.hashCode()
        return result
    }
}
