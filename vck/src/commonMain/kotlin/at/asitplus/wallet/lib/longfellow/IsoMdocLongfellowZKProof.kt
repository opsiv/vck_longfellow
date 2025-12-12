package at.asitplus.wallet.lib.longfellow

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSignedList
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.toDisclosed
import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.emptyMap
import kotlin.time.Clock
import kotlin.time.Instant

class IsoMdocLongfellowZKProof ( // TODO: inherit from IsoMdocZkProof
    zkDocument: ZkDocument,
    val sessionTranscript: SessionTranscript,
) {
    val circuit: Circuit
    val issuerKey: CryptoPublicKey.EC // TODO think about getting it from DRO
    val timestamp: Instant // TODO think about getting it from DRO
    val namespaces: Map<String, ZkSignedList>
    val rawProof: ByteArray
    val docType: String // TODO think about getting it from DRO
    val msoX5Chain: List<ByteArray>?

    init {
        msoX5Chain = zkDocument.zkDocumentDataBytes.value.certificateChain
        val certificateHead = msoX5Chain?.firstOrNull()
            ?: throw IllegalArgumentException("No issuer certificate in header")
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
            throw IllegalArgumentException("Could not parse issuer certificate from header", it)
        }
        issuerKey = x509Certificate.decodedPublicKey.getOrNull() as? CryptoPublicKey.EC
            ?: throw IllegalArgumentException("Could not parse key from certificate")

        docType = zkDocument.zkDocumentDataBytes.value.docType
        circuit = Circuit(
            // TODO: automatically gather the correct systemName from somewhere else.
            //  Better let circuit be so abstract that it just tries different registered(=available) providers
            systemName = "longfellow-libzk-v1",
            circuitId = zkDocument.zkDocumentDataBytes.value.zkSystemId
        )
        namespaces = zkDocument.zkDocumentDataBytes.value.issuerSigned ?: emptyMap()
        timestamp = zkDocument.zkDocumentDataBytes.value.timestamp.truncateToSeconds()
        rawProof = zkDocument.proof
    }

    private val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)


    fun verify(): Boolean {
        return NativeLibrary.verifyProof(
            circuit.raw, issuerKey, transcriptBytes, namespaces,
            timestamp, rawProof, docType, circuit.handle
        ).getOrThrow()
    }

    fun toZkDocument(): ZkDocument = ZkDocument(
        zkDocumentDataBytes = ByteStringWrapper(
            ZkDocumentData(
                docType = docType,
                zkSystemId = circuit.circuitId,
                timestamp = timestamp,
                issuerSigned = namespaces,
                // TODO: maybe adjust deviceSigned, since it does affect the deviceAuthentication and
                //  also allows making some statements as prover
                deviceSigned = emptyMap(),
                certificateChain = msoX5Chain
            )
        ),
        proof = rawProof,
    )

    companion object {
        private fun isIso8601Compliant(validityInfo: ValidityInfo?): Boolean {
            return validityInfo?.let{
                it.validFrom.nanosecondsOfSecond == 0 &&
                        it.validUntil.nanosecondsOfSecond == 0 &&
                        it.signed.nanosecondsOfSecond == 0
            } ?: false
        }

        fun generate(
            circuit: Circuit,
            sessionTranscript: SessionTranscript,
            deviceResponse: DeviceResponse,
        ): IsoMdocLongfellowZKProof {
            val document = deviceResponse.documents?.singleOrNull()
                ?: throw IllegalStateException("No or too many documents found!")

            if (!isIso8601Compliant(document.issuerSigned.issuerAuth.payload?.validityInfo))
                throw IllegalStateException("Timestamps do not follow ISO-8601 (precision to seconds)")

            // TODO: attribute count and circuit validation with
            //  val attributeCount = namespaces.values.sumOf { it.entries.size }

            val msoX5Chain = document.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain

            val certificateHead = msoX5Chain?.firstOrNull()
                ?: throw IllegalArgumentException("No issuer certificate in header")
            val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
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
            )
        }
    }
}