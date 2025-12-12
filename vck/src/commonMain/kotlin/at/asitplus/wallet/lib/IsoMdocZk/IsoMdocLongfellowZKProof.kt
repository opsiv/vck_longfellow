package at.asitplus.wallet.lib.IsoMdocZk

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.toDisclosed
import at.asitplus.wallet.lib.longfellow.Circuit
import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Clock
import kotlin.time.Instant

class IsoMdocLongfellowZKProof ( // TODO: inherit from IsoMdocZkProof
    val zkSystem: ZkSystemSpec,
    zkDocument: ZkDocument,
    val sessionTranscript: SessionTranscript,
) {
    val circuit: Circuit
    val issuerKey: CryptoPublicKey.EC
    val timestamp: Instant
    val issuerSignedNamespaces: Map<String, ZkSignedList>
    val deviceSignedNamespaces: Map<String, ZkSignedList>
    val rawProof: ByteArray
    val docType: String
    val msoX5Chain: List<ByteArray>?

    init {
        // TODO: Consider more elaborate checks (versions etc)
        require (SYSTEM == zkSystem.system && zkSystem.params.keys.contains(CIRCUIT_HASH)) {
            "Incompatible ZkSystem, ${zkSystem.system}"
        }
        circuit = Circuit(
            systemName = SYSTEM,
            circuitId = zkSystem.params.getOrElse(CIRCUIT_HASH) {
                throw IllegalArgumentException("No circuit hash provided")
            }
        )

        msoX5Chain = zkDocument.zkDocumentDataBytes.value.certificateChain
        val certificateHead = msoX5Chain?.firstOrNull()
            ?: throw IllegalArgumentException("No issuer certificate in header")
        val x509Certificate = X509Certificate.Companion.decodeFromDerSafe(certificateHead).getOrElse {
            throw IllegalArgumentException("Could not parse issuer certificate from header", it)
        }
        issuerKey = x509Certificate.decodedPublicKey.getOrNull() as? CryptoPublicKey.EC
            ?: throw IllegalArgumentException("Could not parse key from certificate")

        // TODO: consider requiring that deviceSigned is null, because Longfellow doesn't support them yet
        deviceSignedNamespaces = zkDocument.zkDocumentDataBytes.value.deviceSigned ?: emptyMap()
        issuerSignedNamespaces = zkDocument.zkDocumentDataBytes.value.issuerSigned ?: emptyMap()

        docType = zkDocument.zkDocumentDataBytes.value.docType
        // TODO: check if timestamp is fine, and throw if not
        timestamp = zkDocument.zkDocumentDataBytes.value.timestamp.truncateToSeconds()
        rawProof = zkDocument.proof
    }

    private val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)


    fun verify(): Boolean {
        return NativeLibrary.verifyProof(
            circuit.raw, issuerKey, transcriptBytes, issuerSignedNamespaces,
            timestamp, rawProof, docType, circuit.handle
        ).getOrThrow()
    }

    fun toZkDocument(): ZkDocument = ZkDocument(
        zkDocumentDataBytes = ByteStringWrapper(
            ZkDocumentData(
                docType = docType,
                zkSystemId = circuit.circuitId,
                timestamp = timestamp,
                issuerSigned = issuerSignedNamespaces,
                deviceSigned = deviceSignedNamespaces,
                certificateChain = msoX5Chain
            )
        ),
        proof = rawProof,
    )

    companion object {
        private val CIRCUIT_HASH = "circuit_hash"
        private val SYSTEM = "longfellow-libzk-v1"

        // TODO: delete this. It is just a sanity check, because during development, we didnt properly follow the ISO spec
        private fun isIso8601Compliant(validityInfo: ValidityInfo?): Boolean {
            return validityInfo?.let{
                it.validFrom.nanosecondsOfSecond == 0 &&
                        it.validUntil.nanosecondsOfSecond == 0 &&
                        it.signed.nanosecondsOfSecond == 0
            } ?: false
        }

        fun generate(
            zkSystem: ZkSystemSpec,
            sessionTranscript: SessionTranscript,
            deviceResponse: DeviceResponse,
        ): IsoMdocLongfellowZKProof {
            val document = deviceResponse.documents?.singleOrNull()
                ?: throw IllegalStateException("No or too many documents found!")

            if (!isIso8601Compliant(document.issuerSigned.issuerAuth.payload?.validityInfo))
                throw IllegalStateException("Timestamps do not follow ISO-8601 (precision to seconds)")

            // TODO: attribute count and circuit validation with
            //  val attributeCount = namespaces.values.sumOf { it.entries.size }
            require (SYSTEM == zkSystem.system && zkSystem.params.keys.contains(CIRCUIT_HASH)) {
                "Incompatible ZkSystem, ${zkSystem.system}"
            }
            val circuit = Circuit(
                systemName = SYSTEM,
                circuitId = zkSystem.params.getOrElse(CIRCUIT_HASH) {
                    throw IllegalArgumentException("No circuit hash provided")
                }
            )


            val msoX5Chain = document.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain

            val certificateHead = msoX5Chain?.firstOrNull()
                ?: throw IllegalArgumentException("No issuer certificate in header")
            val x509Certificate = X509Certificate.Companion.decodeFromDerSafe(certificateHead).getOrElse {
                throw IllegalArgumentException("Could not parse issuer certificate from header", it)
            }
            val issuerKey = x509Certificate.decodedPublicKey.getOrNull() as? CryptoPublicKey.EC
                ?: throw IllegalArgumentException("Could not parse key from certificate")

            val issuerSignedNamespaces = document.issuerSigned.namespaces.toDisclosed() ?: emptyMap()
            val docType = document.docType
            val deviceSignedNamespaces = document.deviceSigned.namespaces.value.entries.toDisclosed() ?: emptyMap()

            val deviceResponseBytes = coseCompliantSerializer.encodeToByteArray(deviceResponse)
            val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
            val now = Clock.System.now().truncateToSeconds()

            val rawProof = NativeLibrary.generateProof(
                circuit.raw, deviceResponseBytes,
                issuerKey, transcriptBytes, now, issuerSignedNamespaces,
                circuit.handle
            ).getOrThrow()

            val zkDocument = ZkDocument(
                zkDocumentDataBytes = ByteStringWrapper(
                    ZkDocumentData(
                        docType = docType,
                        zkSystemId = circuit.circuitId,
                        timestamp = now,
                        issuerSigned = issuerSignedNamespaces,
                        deviceSigned = deviceSignedNamespaces,
                        certificateChain = msoX5Chain
                    )
                ),
                proof = rawProof
            )

            return IsoMdocLongfellowZKProof(
                zkDocument = zkDocument,
                sessionTranscript = sessionTranscript,
                zkSystem = zkSystem,
            )
        }
    }
}