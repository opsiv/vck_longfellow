package at.asitplus.wallet.lib.longfellow

import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.LongfellowZkBackend
import at.asitplus.wallet.lib.longfellow.longfellowzk.ZkSpecHandle
import io.github.aakira.napier.Napier
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray

data class LongfellowZkParams(
    val systemName: String,
    val circuitId: String,
    private val provider: LongfellowZkHandleAndCircuitProvider
) {
    val circuit: ByteArray by lazy { provider.getCircuit(this) }
    val handle: ZkSpecHandle by lazy { provider.getHandle(this) }
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
    private val baseDir: Path
) : LongfellowZkHandleAndCircuitProvider {
    override fun getHandle(params: LongfellowZkParams): ZkSpecHandle {
        return handleCache.getOrPut(params.circuitId) {
            Napier.d("Fetching circuit handle fir ${params.circuitId}")
            delegate.getHandle(params)
        }
    }

    override fun getCircuit(params: LongfellowZkParams): ByteArray {
        val key = params.circuitId
        return circuitCache.getOrPut(key) {
            val path = Path(baseDir, "$key.circuit")
            if (SystemFileSystem.exists(path)) {
                Napier.d("Loading circuit from file cache : $path")
                return@getOrPut SystemFileSystem.source(path).buffered().readByteArray()
            }
            val circuit = delegate.getCircuit(params)
            try {
                if (!SystemFileSystem.exists(path)) {
                    SystemFileSystem.createDirectories(baseDir)
                }
                SystemFileSystem.sink(path).buffered().use { it.write(circuit) }
                Napier.d("Stored circuit to file $path")
            } catch (e: Exception) {
                Napier.d("Could not persist circuit to file: ${e.message}")
            }
            circuit
        }
    }
    companion object {
        private val circuitCache = mutableMapOf<String, ByteArray>()
        private val handleCache = mutableMapOf<String, ZkSpecHandle>()
    }
}
