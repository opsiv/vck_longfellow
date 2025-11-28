package at.asitplus.wallet.lib.agent

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MdocProof
import at.asitplus.iso.ResponseItem
import at.asitplus.iso.SessionTranscript
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.cbor.publicKey
import at.asitplus.wallet.lib.longfellow.AnySerializer
import at.asitplus.wallet.lib.longfellow.Circuit
import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import at.asitplus.wallet.lib.longfellow.truncateToSecond
import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.time.Clock

/**
 * Strategy interface to allow for multiple possible ISO-Mdoc presentations
 * e.g. Plain presentation vs Longfellow-Zk presentations
 */
sealed class IsoPresentationStrategy {
    abstract suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): CreatePresentationResult

    protected suspend fun createDeviceResponse(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>
    ): DeviceResponse {
        val documents = credentialAndRequestedClaims.map { (credential, requestedClaims) ->
            // allows disclosure of attributes from different namespaces
            val namespaceToAttributesMap = requestedClaims.mapNotNull { normalizedJsonPath ->
                // namespace + attribute
                val firstTwoNameSegments = normalizedJsonPath.segments.filterIndexed { index, _ ->
                    // TODO: unsure how to deal with attributes with a depth of more than 2
                    //  revealing the whole attribute for now, which is as fine grained as MDOC can do anyway
                    index < 2
                }.filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
                if (firstTwoNameSegments.size == 2) {
                    val namespace = firstTwoNameSegments[0].memberName
                    val attributeName = firstTwoNameSegments[1].memberName
                    namespace to attributeName
                } else {
                    // TODO: Not a namespaced attribute, how to deal with these?
                    //  treating them as fields that are inherent to the credential for now
                    //  -> no need for selective disclosure
                    null
                }
            }.groupBy {
                it.first  // grouping by namespace
            }.mapValues {
                // unrolling values to just the list of attribute names for that namespace
                it.value.map { it.second }
            }
            val disclosedItems = namespaceToAttributesMap.mapValues { namespaceToAttributeNamesEntry ->
                val namespace = namespaceToAttributeNamesEntry.key
                val attributeNames = namespaceToAttributeNamesEntry.value
                attributeNames.map { attributeName ->
                    credential.issuerSigned.namespaces?.get(
                        namespace
                    )?.entries?.find {
                        it.value.elementIdentifier == attributeName
                    }?.value
                        ?: throw PresentationException("Attribute not available in credential: $['$namespace']['$attributeName']")
                }
            }

            val docType = credential.scheme?.isoDocType ?: credential.issuerSigned.issuerAuth.payload?.docType
            ?: throw PresentationException("Scheme not known or not registered")
            val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(mapOf()))
            val input = IsoDeviceSignatureInput(docType, deviceNameSpaceBytes)
            val deviceSignature = request.calcIsoDeviceSignaturePlain(input)
                ?: throw PresentationException("calcIsoDeviceSignature not implemented")

            Document(
                docType = docType,
                issuerSigned = IssuerSigned.fromIssuerSignedItems(
                    namespacedItems = disclosedItems,
                    issuerAuth = credential.issuerSigned.issuerAuth
                ),
                deviceSigned = DeviceSigned(
                    namespaces = deviceNameSpaceBytes,
                    deviceAuth = DeviceAuth(
                        deviceSignature = deviceSignature
                    )
                )
            )
        }
        return DeviceResponse(
            version = "1.0",
            documents = documents.toTypedArray(),
            status = 0U,
        )
    }

    object Plain : IsoPresentationStrategy() {
        override suspend fun createPresentation(
            request: PresentationRequestParameters,
            credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>
        ): CreatePresentationResult {
            Napier.d("createIsoPresentation with $request and $credentialAndRequestedClaims")
            return CreatePresentationResult.DeviceResponse(
                deviceResponse = createDeviceResponse(
                    request = request,
                    credentialAndRequestedClaims = credentialAndRequestedClaims,
                ),
                mdocGeneratedNonce = request.mdocGeneratedNonce
            )
        }
    }

    class LongfellowZk(
        private val zkSystemName: String? = null,
        private val circuitHash: String? = null,
    ) : IsoPresentationStrategy() {
        override suspend fun createPresentation(
            request: PresentationRequestParameters,
            credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>
        ): CreatePresentationResult {
            Napier.d("createIsoPresentation with $request and $credentialAndRequestedClaims")
            val deviceResponse = createDeviceResponse(
                request = request,
                credentialAndRequestedClaims = credentialAndRequestedClaims,
            )

            // TODO: ensure only one doctype and only one **namespace** exists (LF cant handle more than that)
            val document: Document = deviceResponse.documents?.singleOrNull()
                ?: throw IllegalStateException("No or too many documents found!")

            // TODO: mdocGeneratedNonce to SessionTranscript (i think more or less done)
            //  Check if sessionTranscript empty and error out if so. compare with what is done if the request.calcIsoDeviceSignaturePlain.invoke() was empty i guess
            val sessionTranscript: SessionTranscript = request.calcSessionTranscript()
                ?: throw IllegalStateException("No Session Transcript found!")

            // TODO: get issuer-pk from somewhere (i think done, but need to reevaluate if there is a better place)
            val issuerPublicKey: CryptoPublicKey.EC = document
                .issuerSigned.issuerAuth
                .unprotectedHeader?.publicKey
                ?.toCryptoPublicKey()?.getOrNull() as? CryptoPublicKey.EC
                ?: throw IllegalStateException("No Issuer Public Key found in credential!")

            // TODO: check if the precision implementation for the Native API is implemented correctly
            val now = Clock.System.now().truncateToSecond()

            // TODO: i dont like the current version of anyserializer. i should fix this for sth more generic.
            //  Long term, we dont want to serialize here at all yet (cborValue should just be value here)
            //  but for now it works, so lets keep it for prototyping
            val attributes: List<ResponseItem> = mutableListOf<ResponseItem>().apply {
                val issuedNameSpaces = document.issuerSigned.namespaces
                issuedNameSpaces?.entries?.forEach { (nameSpaceId, issuerSignedList) ->
                    issuerSignedList.entries.forEach { item ->
                        val id = item.value.elementIdentifier
                        val serializer = CborCredentialSerializer.lookupSerializer(nameSpaceId, id)
                            ?: AnySerializer
                        val cborValue = coseCompliantSerializer.encodeToByteArray(
                            serializer as KSerializer<Any>,
                            item.value.elementValue
                        )
                        add(ResponseItem(nameSpaceId, id, cborValue))
                    }
                }
            }
            val transcriptBytes = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
            val droBytes = coseCompliantSerializer.encodeToByteArray(deviceResponse)

            val circuit = if (circuitHash != null && zkSystemName != null) {
                Circuit(
                    systemName = zkSystemName,
                    circuitId = circuitHash,
                )
            } else {
                Circuit.forResponseItems(attributes.size)
            }

            val rawProof = NativeLibrary.generateProof(
                circuit.raw, droBytes,
                issuerPublicKey, transcriptBytes, now, attributes,
                circuit.handle).getOrThrow()

            // TODO: think about what to return. is the mdoc generated nonce enough fpr the verifier to be able to verify?
            //  Find out how this is done in the standard verification process (non LF) and just do it exactly like that
            return CreatePresentationResult.MdocProof(
                mdocProof = MdocProof(
                    proof = rawProof,
                    timestamp = now,
                    attributes = attributes,
                    doctype = document.docType,
                    zkSystem = circuit.systemName,
                    circuitHash = circuit.circuitId,
                ),
                mdocGeneratedNonce = request.mdocGeneratedNonce
            )
        }
    }
    companion object {
        val Default = Plain
    }
}
