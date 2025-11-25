package at.asitplus.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class FormatContainerZk (
    @SerialName("zk_system_spec")
    val zkSystemSpecs: List<ZkSystemSpec>? = null,
)
