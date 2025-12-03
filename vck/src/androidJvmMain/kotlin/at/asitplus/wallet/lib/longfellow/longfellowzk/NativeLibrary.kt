package at.asitplus.wallet.lib.longfellow.longfellowzk

import at.asitplus.KmmResult
import at.asitplus.iso.DisclosedList
import at.asitplus.iso.ResponseItem
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.longfellow.keysAsHexStrings
import at.asitplus.wallet.lib.longfellow.longfellowzk.jna.JnaLibrary
import at.asitplus.wallet.lib.longfellow.longfellowzk.jna.toStructArray
import at.asitplus.wallet.lib.longfellow.nativeBuffer.ScopedNativeBuffer
import at.asitplus.wallet.lib.longfellow.toKmmResultIfNotNull
import kotlin.time.Instant

actual object NativeLibrary {

    actual fun findZkSpec(systemName: String, circuitHash: String): KmmResult<at.asitplus.wallet.lib.longfellow.longfellowzk.ZkSpecHandle> {
        return JnaLibrary.find_zk_spec(systemName, circuitHash).toKmmResultIfNotNull()
    }
    actual fun generateCircuit(zkSpec: at.asitplus.wallet.lib.longfellow.longfellowzk.ZkSpecHandle): KmmResult<ByteArray> {
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
        deviceResponseObject: ByteArray,
        issuerPublicKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        timestamp: Instant,
        attributes: Map<String, DisclosedList>,
        zkSpec: ZkSpecHandle,
    ): KmmResult<ByteArray> {
        val attributeStructs = attributes.toStructArray()
        val result =  ScopedNativeBuffer { pointers ->
            JnaLibrary.run_mdoc_prover(
                bcp = circuit, bcsz = circuit.size.toLong(),
                mdoc = deviceResponseObject, mdoc_len = deviceResponseObject.size.toLong(),
                pkx = "0x${issuerPublicKey.publicPoint.x.toString(16)}",
                pky = "0x${issuerPublicKey.publicPoint.y.toString(16)}",
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
        issuerPublicKey: CryptoPublicKey.EC,
        transcript: ByteArray,
        attributes: Map<String, DisclosedList>,
        timestamp: Instant,
        proof: ByteArray,
        docType: String,
        zkSpec: ZkSpecHandle
    ): KmmResult<Boolean> {
        val (pkx, pky) = issuerPublicKey.keysAsHexStrings()
        val attributeStructs = attributes.toStructArray()
        val intCode = JnaLibrary.run_mdoc_verifier(
            bcp = circuit, bcsz = circuit.size.toLong(),
            pkx = pkx,
            pky = pky,
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

