package at.asitplus.wallet.lib.isoMdocZk

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

class IsoMdocLongfellowZKProof (
    override val zkSystemSpec: ZkSystemSpec,
    zkDocument: ZkDocument,
    val sessionTranscript: SessionTranscript,
) : IsoMdocZkProof() {
    val circuit: Circuit
    val issuerKey: CryptoPublicKey.EC
    override val timestamp: Instant
    override val issuerSignedNamespaces: Map<String, ZkSignedList>
    override val deviceSignedNamespaces: Map<String, ZkSignedList>
    override val rawProof: ByteArray
    override val docType: String
    override val msoX5Chain: List<ByteArray>?

    init {
        validateSystem(zkSystemSpec)
        circuit = buildCircuit(zkSystemSpec)

        msoX5Chain = zkDocument.zkDocumentDataBytes.value.certificateChain
        issuerKey = extractIssuerKey(msoX5Chain)

        // TODO: consider requiring that deviceSigned is null, because Longfellow doesn't support them yet
        deviceSignedNamespaces = zkDocument.zkDocumentDataBytes.value.deviceSigned ?: emptyMap()
        issuerSignedNamespaces = zkDocument.zkDocumentDataBytes.value.issuerSigned ?: emptyMap()

        docType = zkDocument.zkDocumentDataBytes.value.docType
        // TODO: check if timestamp is fine, and throw if not
        timestamp = zkDocument.zkDocumentDataBytes.value.timestamp.truncateToSeconds()
        rawProof = zkDocument.proof
    }

    private val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)


    override fun verify(): Boolean {
        return NativeLibrary.verifyProof(
            circuit.raw, issuerKey, transcriptBytes, issuerSignedNamespaces,
            timestamp, rawProof, docType, circuit.handle
        ).getOrThrow()
    }

    companion object Factory : IsoMdocZkProofFactory {
        private const val circuitHashIdentifier = "circuit_hash"
        const val systemIdentifier = "longfellow-libzk-v1"

        override fun supports(zkSystemSpec: ZkSystemSpec): Boolean {
            // TODO: Consider more validation eg with
            //  attribute count and circuit validation with
            //  val attributeCount = namespaces.values.sumOf { it.entries.size }
            return zkSystemSpec.system == systemIdentifier &&
                    zkSystemSpec.params.containsKey(circuitHashIdentifier)
        }

        override fun generate(
            zkSystemSpec: ZkSystemSpec,
            sessionTranscript: SessionTranscript,
            deviceResponse: DeviceResponse,
        ): IsoMdocZkProof {
            val document = deviceResponse.documents?.singleOrNull()
                ?: throw IllegalStateException("No or too many documents found!")

            // TODO: remove this check
            if (!isIso8601Compliant(document.issuerSigned.issuerAuth.payload?.validityInfo))
                throw IllegalStateException("Timestamps do not follow ISO-8601 (precision to seconds)")

            validateSystem(zkSystemSpec)
            val circuit = buildCircuit(zkSystemSpec)

            val msoX5Chain = document.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain
            val issuerKey = extractIssuerKey(msoX5Chain)

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
                zkSystemSpec = zkSystemSpec,
            )
        }

        override fun load(
            zkDocument: ZkDocument,
            sessionTranscript: SessionTranscript,
            zkSystemSpec: ZkSystemSpec
        ): IsoMdocZkProof {
            return IsoMdocLongfellowZKProof(
                zkDocument = zkDocument,
                sessionTranscript = sessionTranscript,
                zkSystemSpec = zkSystemSpec
            )
        }

        private fun validateSystem(zkSystemSpec: ZkSystemSpec) {
            require (supports(zkSystemSpec)) {
                "Incompatible ZkSystem, ${zkSystemSpec.system}"
            }
        }

        private fun buildCircuit(zkSystemSpec: ZkSystemSpec) = Circuit(
            systemName = systemIdentifier,
            circuitId = zkSystemSpec.params.getOrElse(circuitHashIdentifier) {
                throw IllegalArgumentException("No circuit hash provided")
            }
        )

        // TODO: consider checking the whole list
        private fun extractIssuerKey(msoX5Chain: List<ByteArray>?): CryptoPublicKey.EC {
            val certificateHead = msoX5Chain?.firstOrNull()
                ?: throw IllegalArgumentException("No issuer certificate in header")
            val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
                throw IllegalArgumentException("Could not parse issuer certificate from header", it)
            }
            val issuerKey = x509Certificate.decodedPublicKey.getOrNull() as? CryptoPublicKey.EC
                ?: throw IllegalArgumentException("Could not parse key from certificate")
            return issuerKey
        }
    }
}

// TODO: delete this. It is just a sanity check, because during development, we didnt properly follow the ISO spec
private fun isIso8601Compliant(validityInfo: ValidityInfo?): Boolean {
    return validityInfo?.let{
        it.validFrom.nanosecondsOfSecond == 0 &&
                it.validUntil.nanosecondsOfSecond == 0 &&
                it.signed.nanosecondsOfSecond == 0
    } ?: false
}