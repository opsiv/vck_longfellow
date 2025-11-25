package at.asitplus.wallet.lib.longfellow.longfellowzk

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import kotlin.time.Instant
expect object NativeLibrary {
    fun generateCircuit(zkSpec: ZkSpecHandle): KmmResult<ByteArray>

    fun generateProof(
        circuit: ByteArray,
        deviceResponseObject: ByteArray,
        issuerPublicKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        timestamp: Instant,
        attributes: List<RequestedItem>,
        zkSpec: ZkSpecHandle
    ): KmmResult<ByteArray>

    fun verifyProof(
        circuit: ByteArray,
        issuerPublicKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        attributes: List<RequestedItem>,
        timestamp: Instant,
        proof: ByteArray,
        docType: String,
        zkSpec: ZkSpecHandle
    ): KmmResult<Boolean>

    fun findZkSpec(systemName: String, circuitHash: String): KmmResult<ZkSpecHandle>
}


