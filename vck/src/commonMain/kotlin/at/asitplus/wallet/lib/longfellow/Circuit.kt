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

        private val countToDefaultCircuitHash = mutableMapOf<Int, String>(
            Pair(1, "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"),
            Pair(2, "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e"),
            Pair(3, "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010"),
            Pair(4, "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6")
        )

        fun forResponseItems(count: Int): Circuit {
            val systemName = "longfellow-libzk-v1"
            return Circuit(systemName, countToDefaultCircuitHash.getValue(count))
        }
    }
}