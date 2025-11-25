package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkSystemType(
    @SerialName("id")
    // Set to <circuit_hash> for longfellow
    val id: String,

    @SerialName("systen")
    // set to "longfellow-libzk-v1" for standard longfellow lib
    val systen: String,

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
