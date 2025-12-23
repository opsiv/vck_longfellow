package at.asitplus.wallet.lib.isoMdocZk.longfellowZk

import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.handleAndCircuitProvider.HandleAndCircuitProvider

data class ZkParams(
    val systemName: String,
    val circuitId: String,
    private val provider: HandleAndCircuitProvider
) {
    val circuit: ByteArray by lazy { provider.getCircuit(this) }
    val handle: ZkSpecHandle by lazy { provider.getHandle(this) }
}

