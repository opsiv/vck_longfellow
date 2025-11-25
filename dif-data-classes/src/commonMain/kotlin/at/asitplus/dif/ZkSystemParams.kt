package at.asitplus.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkSystemParams (
    @SerialName("circuit_hash")
    val circuitHash: String,

    @SerialName("num_attributes")
    val numAttributes: Int,

    @SerialName("version")
    val version: Int,

    @SerialName("block_enc_hash")
    val blockEncHash: Int,

    @SerialName("block_enc_sig")
    val blockEncSig: Int,
)
