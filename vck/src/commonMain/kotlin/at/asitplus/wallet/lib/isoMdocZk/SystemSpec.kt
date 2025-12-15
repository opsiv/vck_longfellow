package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.ZkSystemSpec

// TODO: think about moving this into another package, it feels out of place here
data class SystemSpec(
    val allowedZkSpec: List<ZkSystemSpec>,
    val forceZk: Boolean = false
) {
    init {
        require(!forceZk || allowedZkSpec.isNotEmpty()) { "ZkSpec cannot be empty if Zero-Knowledge is enforced" }
    }

    companion object {
        val Default = SystemSpec(listOf(), false)
    }
}
