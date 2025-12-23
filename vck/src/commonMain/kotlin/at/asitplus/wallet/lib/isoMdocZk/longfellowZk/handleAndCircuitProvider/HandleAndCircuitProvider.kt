package at.asitplus.wallet.lib.isoMdocZk.longfellowZk.handleAndCircuitProvider

import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.ZkParams
import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.ZkSpecHandle

interface HandleAndCircuitProvider {
    fun getHandle(params: ZkParams): ZkSpecHandle
    fun getCircuit(params: ZkParams): ByteArray
}