package at.asitplus.wallet.lib.longfellow

import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.LongfellowZkBackend
import at.asitplus.wallet.lib.longfellow.longfellowzk.ZkSpecHandle
import io.github.aakira.napier.Napier
import kotlinx.io.files.FileSystem
import kotlinx.io.files.Path

data class LongfellowZkParams (
    val systemName: String,
    val circuitId: String,
    private val provider: LongfellowZkHandleAndCircuitProvider
) {
    val circuit = provider.getCircuit(this)
    val handle = provider.getHandle(this)
}


interface LongfellowZkHandleAndCircuitProvider {
    fun getHandle(params: LongfellowZkParams): ZkSpecHandle
    fun getCircuit(params: LongfellowZkParams): ByteArray
}

class BackendLongfellowZkHandleAndCircuitProvider(
    private val backend: LongfellowZkBackend
) : LongfellowZkHandleAndCircuitProvider {
    override fun getHandle(params: LongfellowZkParams): ZkSpecHandle =
        backend.findZkSpec(params.systemName, params.circuitId).getOrThrow()

    override fun getCircuit(params: LongfellowZkParams): ByteArray =
        backend.generateCircuit(getHandle(params)).getOrThrow()
}

class FileCachingLongfellowZkProvider(
    private val delegate: LongfellowZkHandleAndCircuitProvider,
    private val baseDir: Path = "longfellow".toPath()
) : LongfellowZkHandleAndCircuitProvider {

    private val fs = FileSystem.SYSTEM
    private val circuitCache = mutableMapOf<String, ByteArray>()
    private val handleCache = mutableMapOf<String, ZkSpecHandle>()

    override fun getHandle(params: LongfellowZkParams): ZkSpecHandle {
        return handleCache.getOrPut(params.circuitId) {
            Napier.d("Fetching circuit handle")
            delegate.getHandle(params)
        }
    }

    override fun getCircuit(params: LongfellowZkParams): ByteArray {
        val key = params.circuitId
        return circuitCache.getOrPut(key) {
            val path = baseDir / "$key.circuit"
            if (fs.exists(path)) {
                return@getOrPut fs.read(path) { readByteArray() }
            }
            val circuit = delegate.getCircuit(params)
            try {
                fs.write(path) { write(circuit) }
            } catch (e: Exception) {
                Napier.d("Could not persist circuit to file: ${e.message}")
            }
            circuit
        }
    }
}
