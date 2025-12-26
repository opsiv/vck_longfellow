package at.asitplus.iso.zk.longfellowZk.backend

import at.asitplus.KmmResult
import at.asitplus.iso.zk.longfellowZk.RequestedItem
import at.asitplus.iso.zk.longfellowZk.ZkSpecHandle
import at.asitplus.iso.zk.longfellowZk.cinterop.RequestedAttribute
import at.asitplus.iso.zk.longfellowZk.cinterop.convertToNative
import at.asitplus.iso.zk.longfellowZk.cinterop.find_zk_spec
import at.asitplus.iso.zk.longfellowZk.cinterop.generate_circuit
import at.asitplus.iso.zk.longfellowZk.cinterop.run_mdoc_prover
import at.asitplus.iso.zk.longfellowZk.cinterop.run_mdoc_verifier
import at.asitplus.iso.zk.longfellowZk.nativeBuffer.ScopedNativeBuffer
import at.asitplus.iso.zk.longfellowZk.resultCode.CircuitResultCode
import at.asitplus.iso.zk.longfellowZk.resultCode.NativeResult
import at.asitplus.iso.zk.longfellowZk.resultCode.NativeResultException
import at.asitplus.iso.zk.longfellowZk.resultCode.ProverResultCode
import at.asitplus.iso.zk.longfellowZk.resultCode.VerifierResultCode
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned

actual object NativeLongfellowZkBackend : LongfellowZkBackend by CinteropLongfellowZkBackend

object CinteropLongfellowZkBackend: LongfellowZkBackend {
    private var initialized = false

    @OptIn(ExperimentalForeignApi::class)
    override fun findZkSpec(systemName: String, circuitHash: String): KmmResult<ZkSpecHandle> {
        require(initialized) { "Citnerop library not initialized" }
        val zkSpecPtr = find_zk_spec(systemName, circuitHash)
        return ZkSpecHandle.toZkSpecHandle(zkSpecPtr).toKmmResultIfNotNull()
    }

    @OptIn(ExperimentalUnsignedTypes::class, ExperimentalForeignApi::class)
    override fun generateCircuit(zkSpec: ZkSpecHandle): KmmResult<ByteArray> {
        require(initialized) { "Citnerop library not initialized" }
        val result = ScopedNativeBuffer { pointers ->
            generate_circuit(
                zk_spec_version = zkSpec.ptr,
                cb = pointers.byteArray.ptr,
                clen = pointers.byteArrayLength.ptr
            ).toInt()
        }
        return NativeResult.fromInt<CircuitResultCode, ByteArray>(result)
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun generateProof(
        circuit: ByteArray,
        deviceResponse: ByteArray,
        publicKeyX: String,
        publicKeyY: String,
        transcript: ByteArray,
        timestamp: String,
        requestedItems: List<RequestedItem>,
        zkSpec: ZkSpecHandle
    ): KmmResult<ByteArray> {
        require(initialized) { "Citnerop library not initialized" }
        transcript.usePinned { pinnedTranscript ->
            val transcriptPtr: CPointer<UByteVar> = pinnedTranscript.addressOf(0).reinterpret()
            circuit.usePinned { pinnedCircuit ->
                val circuitPtr: CPointer<UByteVar> = pinnedCircuit.addressOf(0).reinterpret()
                deviceResponse.usePinned  { pinnedDro ->
                    val droPtr: CPointer<UByteVar> = pinnedDro.addressOf(0).reinterpret()
                    val result = ScopedNativeBuffer { pointers ->
                        memScoped {
                            val attrs: CValuesRef<RequestedAttribute>? = convertToNative(requestedItems)
                            run_mdoc_prover(
                                bcp = circuitPtr, bcsz = circuit.size.toULong(),
                                mdoc = droPtr, mdoc_len = deviceResponse.size.toULong(),
                                pkx = publicKeyX,
                                pky = publicKeyY,
                                transcript = transcriptPtr, transcript.size.toULong(),
                                attrs = attrs, attrs_len =  requestedItems.size.toULong(),
                                now = timestamp,
                                prf = pointers.byteArray.ptr, proof_len = pointers.byteArrayLength.ptr,
                                zk_spec_version = zkSpec.ptr
                            ).toInt()
                        }
                    }
                    return NativeResult.fromInt<ProverResultCode, ByteArray>(result)
                }
            }
        }
    }


    @OptIn(ExperimentalForeignApi::class)
    override fun verifyProof(
        circuit: ByteArray,
        publicKeyX: String,
        publicKeyY: String,
        transcript: ByteArray,
        requestedItems: List<RequestedItem>,
        timestamp: String,
        proof: ByteArray,
        docType: String,
        zkSpec: ZkSpecHandle
    ): KmmResult<Boolean> {
        require(initialized) { "Citnerop library not initialized" }
        transcript.usePinned { pinnedTranscript ->
            val transcriptPtr: CPointer<UByteVar> = pinnedTranscript.addressOf(0).reinterpret()
            circuit.usePinned { pinnedCircuit ->
                val circuitPtr: CPointer<UByteVar> = pinnedCircuit.addressOf(0).reinterpret()
                proof.usePinned { pinnedProof ->
                    val proofPtr: CPointer<UByteVar> = pinnedProof.addressOf(0).reinterpret()
                    memScoped {
                        val attrs: CValuesRef<RequestedAttribute>? = convertToNative(requestedItems)
                        val intCode = run_mdoc_verifier(
                            bcp = circuitPtr, bcsz = circuit.size.toULong(),
                            pkx = publicKeyX,
                            pky = publicKeyY,
                            transcript = transcriptPtr, transcript.size.toULong(),
                            attrs = attrs, requestedItems.size.toULong(),
                            now = timestamp,
                            zkproof = proofPtr, proof_len = proof.size.toULong(),
                            docType = docType,
                            zk_spec_version = zkSpec.ptr
                        ).toInt()
                        val resultCode = VerifierResultCode.fromInt(intCode)
                        return when {
                            resultCode.isSuccess -> KmmResult(true)
                            resultCode in VerifierResultCode.invalidInputs -> KmmResult(false)
                            else ->  KmmResult.failure(NativeResultException(resultCode))
                        }
                    }
                }
            }
        }
    }

    override fun initialize(): KmmResult<Unit> {
        initialized = true
        return KmmResult.success(Unit)
    }

}