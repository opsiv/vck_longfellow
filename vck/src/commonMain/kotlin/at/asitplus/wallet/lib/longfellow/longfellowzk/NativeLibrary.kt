package at.asitplus.wallet.lib.longfellow.longfellowzk

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlin.time.Instant
expect object NativeLibrary {
    fun generateCircuit(zkSpec: ZkSpecHandle): KmmResult<ByteArray>

    fun generateProof(
        circuit: ByteArray,
        deviceResponse: ByteArray,
        issuerKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        timestamp: Instant,
        requestedItems: List<RequestedItem>,
        zkSpec: ZkSpecHandle
    ): KmmResult<ByteArray>

    fun verifyProof(
        circuit: ByteArray,
        issuerKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        requestedItems: List<RequestedItem>,
        timestamp: Instant,
        proof: ByteArray,
        docType: String,
        zkSpec: ZkSpecHandle
    ): KmmResult<Boolean>

    fun findZkSpec(systemName: String, circuitHash: String): KmmResult<ZkSpecHandle>
}


internal fun ModularBigInteger.toPrefixedHexString() = "0x${this.toString(16)}"