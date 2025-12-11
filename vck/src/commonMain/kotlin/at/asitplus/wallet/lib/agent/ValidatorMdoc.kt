package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.dcql.DCQLZkSystemType
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.SuccessIso
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidator
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationDetails
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.IsoZkDocumentParsed
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.longfellow.Circuit
import at.asitplus.wallet.lib.longfellow.Proof
import io.github.aakira.napier.Napier
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.coroutines.cancellation.CancellationException

class ValidatorMdoc(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> =
        VerifyCoseSignatureWithKey(verifySignature),
    /** Structure / Integrity / Semantics validator. */
    private val mdocInputValidator: MdocInputValidator =
        MdocInputValidator(verifyCoseSignatureWithKey = verifyCoseSignatureWithKey),
    private val validator: Validator = Validator(),
) {

    internal suspend fun checkRevocationStatus(issuerSigned: IssuerSigned) =
        validator.checkRevocationStatus(issuerSigned)

    /**
     * Validates an ISO device response, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDeviceResponse(
        deviceResponse: DeviceResponse,
        sessionTranscript: SessionTranscript,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
        validateZkSystemType: ((ZkDocument) -> Boolean)? = null,
    ): VerifyPresentationResult {
        require(deviceResponse.status == 0U) { "status: ${deviceResponse.status}" }
        require(deviceResponse.documents != null || deviceResponse.zkDocuments != null) {
            "documents and zkDocuments are null"
        }
        val hasZkDocuments = !deviceResponse.zkDocuments.isNullOrEmpty()

        if (hasZkDocuments && validateZkSystemType == null) {
            throw IllegalArgumentException("ZkDocuments in response, but no validation possible")
        }

        deviceResponse.zkDocuments?.forEach { zkDocument ->
            val isAllowed = validateZkSystemType?.invoke(zkDocument) ?: false
            require(isAllowed) { "zkDocument not of any allowed zkSystemType" }
        }

        val documents = deviceResponse.documents?.map {
            verifyDocument(it, verifyDocumentCallback)
        } ?: emptyList()

        val zkDocuments = deviceResponse.zkDocuments?.map {
            verifyZkDocument(it, sessionTranscript)
        } ?: emptyList()

        return VerifyPresentationResult.SuccessIso(
            documents = documents,
            zkDocuments = zkDocuments,
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDocument(
        document: Document,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): IsoDocumentParsed {
        require(document.errors == null) { "Errors: ${document.errors}" }
        val issuerSigned = document.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val certificateHead = issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()
            ?: throw IllegalArgumentException("No issuer certificate in header")
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
            throw IllegalArgumentException("Could not parse issuer certificate from header", it)
        }
        val issuerKey = x509Certificate.decodedPublicKey.getOrThrow().toCoseKey().getOrElse {
            throw IllegalArgumentException("Could not parse key from certificate", it)
        }

        verifyCoseSignatureWithKey(issuerAuth, issuerKey, byteArrayOf(), null).onFailure {
            throw IllegalArgumentException("IssuerAuth not verified", it)
        }

        val mso: MobileSecurityObject? = issuerSigned.issuerAuth.payload
        require(mso != null) { "mso is null" }
        require(mso.docType == document.docType) {
            "mso.docType '${mso.docType}' does not match Doc docType '${document.docType}'"
        }
        require(verifyDocumentCallback.invoke(mso, document)) {
            "document callback failed: $document"
        }

        val validItems = mutableListOf<IssuerSignedItem>()
        val invalidItems = mutableListOf<IssuerSignedItem>()
        issuerSigned.namespaces?.forEach { (namespace, issuerSignedItems) ->
            issuerSignedItems.entries.forEach {
                if (it.verify(mso.valueDigests[namespace])) {
                    validItems += it.value
                } else {
                    invalidItems += it.value
                }
            }
        }
        return IsoDocumentParsed(
            document = document,
            mso = mso,
            validItems = validItems,
            invalidItems = invalidItems,
            freshnessSummary = validator.checkCredentialFreshness(issuerSigned),
        )
    }

    /**
     * Validates an ISO ZkDocument, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyZkDocument(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
    ): IsoZkDocumentParsed {
        // extract Issuer signing key
        val certificateHead = zkDocument.zkDocumentDataBytes.value.certificateChain?.firstOrNull()
            ?: throw IllegalArgumentException("No issuer certificate in header")
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
            throw IllegalArgumentException("Could not parse issuer certificate from header", it)
        }
        val issuerKey = x509Certificate.decodedPublicKey.getOrNull() as? CryptoPublicKey.EC
            ?: throw IllegalArgumentException("Could not parse key from certificate")

        val docType = zkDocument.zkDocumentDataBytes.value.docType
        val circuit = Circuit(
            // TODO: automatically gather the correct systemName from somewhere else.
            //  Better let circuit be so abstract that it just tries different registered(=available) providers
            systemName = "longfellow-libzk-v1",
            circuitId = zkDocument.zkDocumentDataBytes.value.zkSystemId
        )
        val namespaces = zkDocument.zkDocumentDataBytes.value.issuerSigned ?: emptyMap()
        val timestamp = zkDocument.zkDocumentDataBytes.value.timestamp.truncateToSeconds()
        val rawProof = zkDocument.proof
        val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)

        val proof = Proof(
            circuit = circuit,
            transcript = transcriptBytes,
            issuerPublicKey = issuerKey,
            timestamp = timestamp,
            namespaces = namespaces,
            zkProof = rawProof,
            docType = docType
        )

        val allItems = zkDocument.zkDocumentDataBytes.value.issuerSigned
            ?.values
            ?.flatMap { it.entries }
            ?: emptyList()

        val (validItems, invalidItems) = if (proof.verify()) {
            allItems to emptyList()
        } else {
            emptyList<ZkSignedItem>() to allItems
        }

        // TODO: check somewhere if this is even allowed to be proven in ZK (i.e. through some kind of callback?)
        return IsoZkDocumentParsed(
            zkDocument = zkDocument,
            validItems = validItems,
            invalidItems = invalidItems,
            // TODO: fix freshnessSummary
            freshnessSummary = CredentialFreshnessSummary.Mdoc(
                timelinessValidationSummary = CredentialTimelinessValidationSummary.Mdoc(
                    details = MdocTimelinessValidationDetails(
                        evaluationTime = timestamp,
                        msoTimelinessValidationSummary = null,
                    )
                ),
                tokenStatusValidationResult = TokenStatusValidationResult.Valid(null)
            ),
        )
    }


    /**
     * Verify that calculated digests equal the corresponding digest values in the MSO.
     *
     * See ISO/IEC 18013-5:2021, 9.3.1 Inspection procedure for issuer data authentication
     */
    private fun ByteStringWrapper<IssuerSignedItem>.verify(mdlItems: ValueDigestList?): Boolean {
        val issuerHash = mdlItems?.entries?.firstOrNull { it.key == value.digestId }
            ?: return false
        val verifierHash = coseCompliantSerializer
            .encodeToByteArray(ByteArraySerializer(), serialized)
            .wrapInCborTag(24)
            .sha256()
        return verifierHash.contentEquals(issuerHash.value)
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    suspend fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        val mdocInputValidator = mdocInputValidator(it, issuerKey)
        if (!mdocInputValidator.isSuccess) {
            return VerifyCredentialResult.ValidationError(
                cause = mdocInputValidator.error ?: IllegalArgumentException("No details available")
            )
        }
        return SuccessIso(it)
    }
}
