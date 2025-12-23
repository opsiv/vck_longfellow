package at.asitplus.wallet.lib.isoMdocZk.longfellowZk

import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.backend.LongfellowZkBackend
import at.asitplus.wallet.lib.isoMdocZk.longfellowZk.ZkSpecHandle
import io.github.aakira.napier.Napier
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray

data class ZkParams(
    val systemName: String,
    val circuitId: String,
    private val provider: HandleAndCircuitProvider
) {
    val circuit: ByteArray by lazy { provider.getCircuit(this) }
    val handle: ZkSpecHandle by lazy { provider.getHandle(this) }
}


interface HandleAndCircuitProvider {
    fun getHandle(params: ZkParams): ZkSpecHandle
    fun getCircuit(params: ZkParams): ByteArray
}

class BasicHandleAndCircuitProvider(
    private val backend: LongfellowZkBackend
) : HandleAndCircuitProvider {
    override fun getHandle(params: ZkParams): ZkSpecHandle =
        backend.findZkSpec(params.systemName, params.circuitId).getOrThrow()

    override fun getCircuit(params: ZkParams): ByteArray =
        backend.generateCircuit(getHandle(params)).getOrThrow()
}

// TODO: make a better file-based or DB-based provider
class PersistentHandleAndCircuitProvider(
    private val delegate: HandleAndCircuitProvider,
    private val baseDir: Path
) : HandleAndCircuitProvider {
    private val circuitCache = mutableMapOf<String, ByteArray>()
    private val handleCache = mutableMapOf<String, ZkSpecHandle>()

    override fun getHandle(params: ZkParams): ZkSpecHandle {
        return handleCache.getOrPut(params.circuitId) {
            Napier.d("Fetching circuit handle fir ${params.circuitId}")
            delegate.getHandle(params)
        }
    }

    override fun getCircuit(params: ZkParams): ByteArray {
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
}
