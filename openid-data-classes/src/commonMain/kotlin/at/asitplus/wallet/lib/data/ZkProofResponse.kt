package at.asitplus.wallet.lib.data

import at.asitplus.dif.ResponseItem
import at.asitplus.dif.ZkSystemSpec
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ZkProofResponse(
    @SerialName("prood_payload")
    val proofPayload: ByteArray,

    @SerialName("disclosed_attributes")
    val disclosedAttributes: List<ResponseItem>,

    @SerialName("zk_system_spec")
    val zkSystemSpec: ZkSystemSpec,

    @SerialName("doc_type")
    val docType: String,

    @SerialName("proof_time")
    val proofTime: Instant,

    // TODO: think about including circuit (=zkSpec) again
    // TODO: think about including transcript
    // TODO: think about including issuerPubkey
    // TODO: Think about including a RequestItem List, which is like RequestItem (just w/o the value), for the verifier to understand what was requested vs what was responded
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ZkProofResponse

        if (!proofPayload.contentEquals(other.proofPayload)) return false
        if (disclosedAttributes != other.disclosedAttributes) return false
        if (zkSystemSpec != other.zkSystemSpec) return false
        if (docType != other.docType) return false
        if (proofTime != other.proofTime) return false

        return true
    }

    override fun hashCode(): Int {
        var result = proofPayload.contentHashCode()
        result = 31 * result + disclosedAttributes.hashCode()
        result = 31 * result + zkSystemSpec.hashCode()
        result = 31 * result + docType.hashCode()
        result = 31 * result + proofTime.hashCode()
        return result
    }
}
