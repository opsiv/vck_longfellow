package at.asitplus.wallet.lib.longfellow

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import at.asitplus.wallet.lib.longfellow.longfellowzk.RequestedItem
import kotlin.time.Instant

class Proof (
    val circuit: Circuit,
    val transcript: ByteArray,
    val issuerPublicKey: CryptoPublicKey.EC, // TODO think about getting it from DRO
    val timestamp: Instant, // TODO think about getting it from DRO
    val attributes: List<RequestedItem>,
    val zkProof: ByteArray,
    val docType: String // TODO think about getting it from DRO
) {
    fun verify(): Boolean {
        return NativeLibrary.verifyProof(
            circuit.raw, issuerPublicKey, transcript, attributes,
            timestamp, zkProof, docType, circuit.handle
        ).getOrThrow()
    }

    companion object {
        fun generate(
            circuit: Circuit,
            transcript: ByteArray,
            issuerPublicKey: CryptoPublicKey.EC,
            timestamp: Instant,
            attributes: List<RequestedItem>,
            deviceResponseObject: ByteArray, // TODO Replace with serializable object
            docType: String,
        ): Proof {
            val zkp = NativeLibrary.generateProof(
                circuit.raw, deviceResponseObject,
                issuerPublicKey, transcript, timestamp, attributes,
                circuit.handle
            ).getOrThrow()

            return Proof(
                circuit, transcript, issuerPublicKey,
                timestamp, attributes, zkp, docType
            )
        }
    }
}