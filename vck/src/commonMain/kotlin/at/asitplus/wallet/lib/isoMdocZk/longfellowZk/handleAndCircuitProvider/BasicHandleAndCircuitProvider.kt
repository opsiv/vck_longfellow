package at.asitplus.wallet.lib.isoMdocZk.longfellowZk.handleAndCircuitProvider

import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.ZkParams
import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.ZkSpecHandle
import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.backend.LongfellowZkBackend

class BasicHandleAndCircuitProvider(
    private val backend: LongfellowZkBackend
) : HandleAndCircuitProvider {
    override fun getHandle(params: ZkParams): ZkSpecHandle =
        backend.findZkSpec(params.systemName, params.circuitId).getOrThrow()

    override fun getCircuit(params: ZkParams): ByteArray =
        backend.generateCircuit(getHandle(params)).getOrThrow()
}