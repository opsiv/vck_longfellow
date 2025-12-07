package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLZkSystemType
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.cbor.publicKey
import at.asitplus.wallet.lib.longfellow.Circuit
import at.asitplus.wallet.lib.longfellow.Proof
import at.asitplus.wallet.lib.longfellow.truncateToSecond
import io.github.aakira.napier.Napier
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

    protected suspend fun buildPlainDocuments(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>
    ): List<Document> {
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
        return documents
    }

    object Plain : IsoPresentationStrategy() {
        override suspend fun createPresentation(
            request: PresentationRequestParameters,
            credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>
        ): CreatePresentationResult {
            Napier.d("createIsoPresentation with $request and $credentialAndRequestedClaims")
            return CreatePresentationResult.DeviceResponse(
                DeviceResponse(
                    version = "1.0",
                    documents = buildPlainDocuments(
                        request = request,
                        credentialAndRequestedClaims = credentialAndRequestedClaims,
                    ).toTypedArray(),
                    status = 0U,
                ),
                mdocGeneratedNonce = request.mdocGeneratedNonce
            )
        }
    }

    class ZeroKnowledge(
        // TODO: change this to List<ZkSystemSpac> and use best fit
        //  See: https://github.com/google/longfellow-zk/blob/69400748daedab509b1c05b771b41c1911fca381/docs/content/en/docs/zk-system-spec.md
        val zkSystemTypes: NonEmptyList<DCQLZkSystemType>
    ) : IsoPresentationStrategy(){

        // instead of creating a DeviceResponse over multiple documents, we first need to create a DeviceResponse
        // for _each_ document. Then with each of these presentations we can assemble a zero knowledge proof ff it
        // satisfies the queries allowed circuit(s) and from that we can then assemble a single DeviceResposne that
        // just puts each of these proofs into zkDocuments and return this single DeviceResposne
        // This is an all-or-nothing approach for now. every document will be converted into a zkp version
        // TODO: change all-or-nothing approach in future revision

        override suspend fun createPresentation(
            request: PresentationRequestParameters,
            credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>
        ): CreatePresentationResult {
            val sessionTranscriptBytes = coseCompliantSerializer.encodeToByteArray(
                request.sessionTranscript
                    ?: throw IllegalStateException("No Session Transcript found!")
            )

            val now = Clock.System.now().truncateToSecond()
            
            val deviceResponses: List<DeviceResponse> = buildPlainDocuments(
                request = request,
                credentialAndRequestedClaims = credentialAndRequestedClaims,
            ).map { document ->
                DeviceResponse(
                    version = "1.0",
                    documents = arrayOf(document),
                    status = 0U,
                )
            }
            // Now we already have 1 device response per document. They should each share the same sessionTranscript,
            // so we can just assemble the session transcript once and then iterate over the list of deviceResponses
            // and then create a zkps. after we have all of them, we create a _single_ new Document and just put the
            // derived proofs in to its zkDocuments. We send that single Document back to the requester

            val zkDocuments = deviceResponses.map { deviceResponse ->
                val document = deviceResponse.documents?.singleOrNull()
                    ?: throw IllegalStateException("No or too many documents found!")

                if (!isIso8601Compliant(document.issuerSigned.issuerAuth.payload?.validityInfo))
                    throw IllegalStateException("Timestamps do not follow ISO-8601 (precision to seconds)")

                // TODO: maybe use something from certificate chain instead?
                val issuerPublicKey: CryptoPublicKey.EC = document
                    .issuerSigned.issuerAuth
                    .unprotectedHeader?.publicKey
                    ?.toCryptoPublicKey()?.getOrNull() as? CryptoPublicKey.EC
                    ?: throw IllegalStateException("No Issuer Public Key found in credential!")

                val namespaces = document.issuerSigned.namespaces.toDisclosed() ?: emptyMap()
                val doctype = document.docType
                val attributeCount = namespaces.values.sumOf { it.entries.size }
                val droBytes = coseCompliantSerializer.encodeToByteArray(deviceResponse)

                val msoX5Chain = document.issuerSigned.issuerAuth.protectedHeader.certificateChain

                // TODO: replace these two!
                val maxVersion: Int? = null
                val minVersion: Int? = 4

                val zkSystemType = zkSystemTypes.filter { it.system == "longfellow-libzk-v1" }
                    .filter { it.numAttributes == attributeCount }
                    .filter {minVersion == null || it.version >= minVersion}
                    .filter {maxVersion == null || it.version <= maxVersion}
                    .maxByOrNull { it.version }
                    ?:  throw IllegalStateException("No matching supported zkSystemType!")

                val circuit = Circuit(
                    zkSystemType.system,
                    zkSystemType.circuitHash
                )

                val proof = Proof.generate(
                    circuit = circuit,
                    transcript = sessionTranscriptBytes,
                    issuerPublicKey = issuerPublicKey,
                    timestamp = now,
                    namespaces = namespaces,
                    deviceResponseObject = droBytes,
                    docType = doctype
                )
                
                ZkDocument(
                    zkDocumentDataBytes = ByteStringWrapper(
                        ZkDocumentData(
                            docType = proof.docType,
                            zkSystemId = proof.circuit.circuitId,
                            timestamp = proof.timestamp,
                            issuerSigned = namespaces,
                            // TODO: maybe adjust deviceSigned, since it might affect the sessionTranscript if deviceNameSpaces is non-empty in the original doc
                            deviceSigned = emptyMap(),
                            certificateChain = msoX5Chain
                        )
                    ),
                    proof = proof.zkProof,
                )
                // TODO there needs to be a try-catch thing to handle documentErrors (and add them to document errors)
            }

            return CreatePresentationResult.DeviceResponse(
                deviceResponse = DeviceResponse(
                    version = "1.0",
                    zkDocuments = zkDocuments.toTypedArray(),
                    status = 0U,
                ),
                mdocGeneratedNonce = request.mdocGeneratedNonce
            )

        }

        private fun isIso8601Compliant(validityInfo: ValidityInfo?): Boolean {
            return validityInfo?.let{
                it.validFrom.nanosecondsOfSecond == 0 &&
                        it.validUntil.nanosecondsOfSecond == 0 &&
                        it.signed.nanosecondsOfSecond == 0
            } ?: false
        }
    }
    companion object {
        val Default = Plain
    }
}

fun Map<String, IssuerSignedList>?.toDisclosed(): Map<String, ZkSignedList>? {
    return this?.mapValues { (_, issuerList) ->
        ZkSignedList(
            entries = issuerList.entries.map { entry ->
                ZkSignedItem(
                    elementIdentifier = entry.value.elementIdentifier,
                    elementValue = entry.value.elementValue
                )
            }
        )
    }
}
