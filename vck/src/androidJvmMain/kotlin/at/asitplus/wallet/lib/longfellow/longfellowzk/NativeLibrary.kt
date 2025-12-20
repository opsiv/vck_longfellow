package at.asitplus.wallet.lib.longfellow.longfellowzk

import at.asitplus.KmmResult
import at.asitplus.iso.ZkSignedList
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.longfellow.longfellowzk.jna.JnaLibrary
import at.asitplus.wallet.lib.longfellow.longfellowzk.jna.toStructArray
import at.asitplus.wallet.lib.longfellow.nativeBuffer.ScopedNativeBuffer
import at.asitplus.wallet.lib.longfellow.toKmmResultIfNotNull
import kotlin.time.Instant

actual object NativeLibrary {

    actual fun findZkSpec(systemName: String, circuitHash: String): KmmResult<ZkSpecHandle> {
        return JnaLibrary.find_zk_spec(systemName, circuitHash)
            .toKmmResultIfNotNull()
    }
    actual fun generateCircuit(zkSpec: ZkSpecHandle): KmmResult<ByteArray> {
        val result = ScopedNativeBuffer { pointers ->
            JnaLibrary.generate_circuit(
                zkSpec,
                pointers.byteArray,
                pointers.byteArrayLength,
            )
        }
        return NativeResult.fromInt<CircuitResultCode, ByteArray>(result)
    }

    actual fun generateProof(
        circuit: ByteArray,
        deviceResponse: ByteArray,
        issuerKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        timestamp: Instant,
        requestedItems: List<RequestedItem>,
        zkSpec: ZkSpecHandle,
    ): KmmResult<ByteArray> {
        val attributeStructs = requestedItems.toStructArray()
        val result =  ScopedNativeBuffer { pointers ->
            JnaLibrary.run_mdoc_prover(
                bcp = circuit, bcsz = circuit.size.toLong(),
                mdoc = deviceResponse, mdoc_len = deviceResponse.size.toLong(),
                pkx = issuerKey.publicPoint.x.toPrefixedHexString(),
                pky = issuerKey.publicPoint.y.toPrefixedHexString(),
                transcript = transcript, tr_len = transcript.size.toLong(),
                attrs = attributeStructs, attrs_len = attributeStructs.size.toLong(),
                now = timestamp.toString(),
                prf = pointers.byteArray, proof_len = pointers.byteArrayLength,
                zkSpec = zkSpec
            )
        }
        return NativeResult.fromInt<ProverResultCode, ByteArray>(result)
    }

    actual fun verifyProof(
        circuit: ByteArray,
        issuerKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        requestedItems: List<RequestedItem>,
        timestamp: Instant,
        proof: ByteArray,
        docType: String,
        zkSpec: ZkSpecHandle
    ): KmmResult<Boolean> {
        val attributeStructs = requestedItems.toStructArray()
        val intCode = JnaLibrary.run_mdoc_verifier(
            bcp = circuit, bcsz = circuit.size.toLong(),
            pkx = issuerKey.publicPoint.x.toPrefixedHexString(),
            pky = issuerKey.publicPoint.y.toPrefixedHexString(),
            transcript = transcript, tr_len = transcript.size.toLong(),
            attrs = attributeStructs, attrs_len = attributeStructs.size.toLong(),
            now = timestamp.toString(),
            prf = proof, proof_len = proof.size.toLong(),
            doc_type = docType,
            zkSpec = zkSpec
        )
        val resultCode = VerifierResultCode.fromInt(intCode)
        return when {
            resultCode.isSuccess -> KmmResult(true)
            resultCode in VerifierResultCode.invalidInputs -> KmmResult(false)
            else ->  KmmResult.failure(NativeResultException(resultCode))
        }
    }
}

