package at.asitplus.wallet.lib.longfellow

import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.LongfellowZkBackend
import at.asitplus.wallet.lib.longfellow.longfellowzk.ZkSpecHandle
import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.provideLongfellowZkBackend
import io.github.aakira.napier.Napier

data class LongfellowZkParams (
    val systemName: String,
    val circuitId: String
) {
    val handle: ZkSpecHandle by lazy {
        getHandle(this)
    }

    val circuit: ByteArray by lazy {
        getRaw(this)
    }

    companion object {
        private val handleCache = mutableMapOf<LongfellowZkParams, ZkSpecHandle>()
        private val circuitCache = mutableMapOf<LongfellowZkParams, ByteArray>()

        private fun getHandle(
            longfellowZkParams: LongfellowZkParams,
            longfellowZkBackend: LongfellowZkBackend = provideLongfellowZkBackend()
        ): ZkSpecHandle {
            return handleCache.getOrPut(longfellowZkParams) {
                Napier.d("Fetching circuit handle")
                longfellowZkBackend.findZkSpec(longfellowZkParams.systemName, longfellowZkParams.circuitId).getOrThrow()
            }
        }
        private fun getRaw(
            longfellowZkParams: LongfellowZkParams,
            longfellowZkBackend: LongfellowZkBackend = provideLongfellowZkBackend()
            ): ByteArray {
            return circuitCache.getOrPut(longfellowZkParams) {
                Napier.d("Generating circuit")
                longfellowZkBackend.generateCircuit(longfellowZkParams.handle).getOrThrow()
            }
        }
    }
}