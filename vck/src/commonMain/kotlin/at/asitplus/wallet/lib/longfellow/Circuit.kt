package at.asitplus.wallet.lib.longfellow

import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import at.asitplus.wallet.lib.longfellow.longfellowzk.ZkSpecHandle
import io.github.aakira.napier.Napier

data class Circuit (
    val systemName: String,
    val circuitId: String
) {
    val handle: ZkSpecHandle by lazy {
        getHandle(this)
    }

    val raw: ByteArray by lazy {
        getRaw(this)
    }

    companion object {
        private val handleCache = mutableMapOf<Circuit, ZkSpecHandle>()
        private val rawCache = mutableMapOf<Circuit, ByteArray>()

        private fun getHandle(circuit: Circuit): ZkSpecHandle {
            return handleCache.getOrPut(circuit) {
                Napier.d("Fetching circuit handle")
                NativeLibrary.findZkSpec(circuit.systemName, circuit.circuitId).getOrThrow()
            }
        }
        private fun getRaw(circuit: Circuit): ByteArray {
            return rawCache.getOrPut(circuit) {
                Napier.d("Generating circuit")
                NativeLibrary.generateCircuit(circuit.handle).getOrThrow()
            }
        }
    }
}