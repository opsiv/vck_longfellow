package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkSystemSpec (
    @SerialName("zkSystemId")
    val zkSystemId: String,
    @SerialName("system")
    val system: String,
    @SerialName("params")
    val params: Map<String, String>
)
