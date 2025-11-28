package at.asitplus.openid.dcql

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ZK System Specification for Mdoc-Zk proofs
 * See: https://github.com/google/longfellow-zk/blob/main/docs/content/en/docs/zk-system-spec.md
 */
@Serializable
data class DCQLZkSystemType (
    @SerialName("id")
    val id: String? = null,

    @SerialName("system")
    val system: String,

    @SerialName("circuit_hash")
    val circuitHash: String,

    @SerialName("num_attributes")
    val numAttributes: Int,

    @SerialName("version")
    val version: Int,

    @SerialName("block_enc_hash")
    val blockEncHash: Int? = null,

    @SerialName("block_enc_sig")
    val blockEncSig: Int? = null,
)