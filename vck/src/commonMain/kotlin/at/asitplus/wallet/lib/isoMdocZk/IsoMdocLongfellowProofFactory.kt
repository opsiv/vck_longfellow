package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.KmmResult
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSignedItemList
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.build
import at.asitplus.wallet.lib.longfellow.LongfellowZkParams
import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.LongfellowZkBackend
import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.provideLongfellowZkBackend
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.time.Clock

class IsoMdocLongfellowZkProofFactory(
    private val backend: LongfellowZkBackend = provideLongfellowZkBackend()
) : IsoMdocZkProofFactory {

    override val systemName = SYSTEM_NAME
    override val paramSerializers = Companion.paramSerializers
    override fun supports(zkSystemSpec: ZkSystemSpec) = Companion.supports(zkSystemSpec)

    override suspend fun generate(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        zkSystemSpec: ZkSystemSpec
    ): IsoMdocZkProof {
        val sessionTranscript = requireNotNull(request.sessionTranscript){"No or too many documents found!"}
        val document = Document.build(
            request = request,
            credential = credential,
            requestedClaims = requestedClaims,
        )
        val deviceResponse = DeviceResponse(
            version = "1.0",
            documents = arrayOf(document),
            status = 0U,
        )


        // TODO: remove this check after migrating to new upstream codebase
        if (!isIso8601Compliant(document.issuerSigned.issuerAuth.payload?.validityInfo))
            throw IllegalStateException("Timestamps do not follow ISO-8601 (precision to seconds)")

        val longfellowZkParams = buildParams(zkSystemSpec)

        val msoX5Chain = document.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain
        val issuerKey = extractIssuerKey(msoX5Chain)

        val issuerZkSignedItems = document.issuerSigned.namespaces.toDisclosed() ?: emptyMap()
        val requestedItems = issuerZkSignedItems.toRequestedItems()
        require(requestedItems.all { it.isValid() }) {
            "Prover can't compute with requested item!"
        }

        val docType = document.docType
        val deviceZkSignedNamespaces = document.deviceSigned.namespaces.value.entries.toDisclosed() ?: emptyMap()


        val deviceResponseBytes = coseCompliantSerializer.encodeToByteArray(deviceResponse)
        val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val now = Clock.System.now().truncateToSeconds()
        val encodedNow = now.toIso8061()

        val (issuerPublicKeyX, issuerPublicKeyY) = issuerKey.toPrefixedHexString()


        val rawProof = backend.generateProof(
            longfellowZkParams.circuit, deviceResponseBytes,
            issuerPublicKeyX, issuerPublicKeyY,
            transcriptBytes, encodedNow,
            requestedItems,
            longfellowZkParams.handle
        ).getOrThrow()

        val sessionTranscriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)

        return IsoMdocLongfellowZKProof.create(
            sessionTranscriptBytes = sessionTranscriptBytes,
            zkSystemSpec = zkSystemSpec,
            backend = backend,
            timestamp = now,
            issuerZkSignedNamespaces = issuerZkSignedItems,
            deviceZkSignedNamespaces = deviceZkSignedNamespaces,
            rawProof = rawProof,
            docType = docType,
            msoX5Chain = msoX5Chain,
        )

    }

    override fun initialize(): KmmResult<Unit> = backend.initialize()

    override fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): IsoMdocZkProof {
        val timestamp = zkDocument.zkDocumentDataBytes.value.timestamp
        require(timestamp.nanosecondsOfSecond == 0) {"Timestamp does not conform to Iso 8601"}
        val msoX5Chain = zkDocument.zkDocumentDataBytes.value.certificateChain
        val docType = zkDocument.zkDocumentDataBytes.value.docType
        val rawProof = zkDocument.proof

        // TODO: consider requiring that deviceSigned is null, because Longfellow doesn't support them yet
        val deviceZkSignedNamespaces = zkDocument.zkDocumentDataBytes.value.deviceSigned ?: emptyMap()
        val issuerZkSignedNamespaces = zkDocument.zkDocumentDataBytes.value.issuerSigned ?: emptyMap()

        val sessionTranscriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        return IsoMdocLongfellowZKProof.create(
            timestamp = timestamp,
            issuerZkSignedNamespaces = issuerZkSignedNamespaces,
            deviceZkSignedNamespaces = deviceZkSignedNamespaces,
            rawProof = rawProof,
            docType = docType,
            msoX5Chain = msoX5Chain,
            zkSystemSpec = zkSystemSpec,
            sessionTranscriptBytes = sessionTranscriptBytes,
            backend = backend,
        )
    }


    companion object {
        internal const val CIRCUIT_HASH_IDENTIFIER = "circuit_hash"
        internal const val NUM_ATTRIBUTES_IDENTIFIER = "num_attributes"
        internal const val VERSION_IDENTIFIER = "version"
        internal const val BLOCK_ENC_HASH_IDENTIFIER = "block_enc_hash"
        internal const val BLOCK_ENC_SIG_IDENTIFIER = "block_enc_sig"
        internal const val SYSTEM_NAME = "longfellow-libzk-v1"

        internal val paramSerializers = mapOf(
            CIRCUIT_HASH_IDENTIFIER to String.serializer(),
            NUM_ATTRIBUTES_IDENTIFIER to Int.serializer(),
            VERSION_IDENTIFIER to Int.serializer(),
            BLOCK_ENC_HASH_IDENTIFIER to Int.serializer(),
            BLOCK_ENC_SIG_IDENTIFIER to Int.serializer(),
        )

        internal fun supports(zkSystemSpec: ZkSystemSpec): Boolean {
            // TODO: Consider more validation eg. with
            //  attribute count and circuit validation with
            //  val attributeCount = namespaces.values.sumOf { it.entries.size }
            return zkSystemSpec.system == SYSTEM_NAME &&
                    zkSystemSpec.params.containsKey(CIRCUIT_HASH_IDENTIFIER)
        }


        // TODO: consider checking the whole list
        internal fun extractIssuerKey(msoX5Chain: List<ByteArray>?): CryptoPublicKey.EC {
            val certificateHead = msoX5Chain?.firstOrNull()
                ?: throw IllegalArgumentException("No issuer certificate in header")
            val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
                throw IllegalArgumentException("Could not parse issuer certificate from header", it)
            }
            val issuerKey = x509Certificate.decodedPublicKey.getOrNull() as? CryptoPublicKey.EC
                ?: throw IllegalArgumentException("Could not parse key from certificate")
            return issuerKey
        }

        internal fun buildParams(zkSystemSpec: ZkSystemSpec) = LongfellowZkParams(
            systemName = SYSTEM_NAME,
            circuitId = zkSystemSpec.params[CIRCUIT_HASH_IDENTIFIER] as? String
                ?: throw IllegalArgumentException("No circuit hash provided")
        )
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

@JvmName("toIssuerDisclosed")
private fun Map<String, IssuerSignedList>?.toDisclosed(): Map<String, ZkSignedList>? = this?.mapValues {
    (_, issuerList) -> ZkSignedList(
        entries = issuerList.entries.map { entry ->
            ZkSignedItem(
                elementIdentifier = entry.value.elementIdentifier,
                elementValue = entry.value.elementValue
            )
        }
    )
}

@JvmName("toDeviceDisclosed")
private fun Map<String, DeviceSignedItemList>?.toDisclosed(): Map<String, ZkSignedList>? = this?.mapValues {
    (_, deviceSignedList) -> ZkSignedList(
        entries = deviceSignedList.entries.map { entry ->
            ZkSignedItem(
                elementIdentifier = entry.key,
                elementValue = entry.value
            )
        }
    )
}

