package at.asitplus.openid

import at.asitplus.dif.ZkSystemSpec
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SupportedZkSystemContainerZk(
    @SerialName("zk_system_specs")
    val zkSystemSpecs: List<ZkSystemSpec>
)
