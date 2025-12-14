package at.asitplus.wallet.lib.agent

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.DeviceSignedItemList
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.ZkDocument
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.isoMdocZk.IsoMdocProofRegistry
import at.asitplus.wallet.lib.isoMdocZk.SystemSpec
import kotlin.collections.component1
import kotlin.collections.component2

object IsoPresentation {
    private suspend fun buildPlainDocuments(
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

    // TODO: Here we ensure that every DeviceResponse has exactly one document inside as preparation for Longfellow,
    //  This means it is very tightly coupled to LongfellowZk.
    //  What we want instead is one credential mapping to one document, just like in the plain version.
    //  Step 1: The ZkSystem should accept the Document directly (instead of the DeviceResponse) and assemble
    //  intermediate representations (such as wrapping into DeviceResponse) by itself
    //  Step 2: The ZkSystem should not even get a document, instead, it should just get one map entry from
    //  credentialAndRequestedClaimsAndSpec and figure out everything else by itself
    //  (this way it is the most self-contained)
    suspend fun createZkDocument(request: PresentationRequestParameters,
         credentialAndRequestedClaimsAndSpec: Map<
                 SubjectCredentialStore.StoreEntry.Iso,
                 Pair<Collection<NormalizedJsonPath>, SystemSpec>
             >,
    ): Collection<ZkDocument> {
        require(request.sessionTranscript != null) {"No or too many documents found!"}
        val deviceResponsesForZk: Map<DeviceResponse, SystemSpec> = credentialAndRequestedClaimsAndSpec
            .filter { (_, claimsAndSpec) ->
                val (_, spec) = claimsAndSpec
                !(spec.allowedZkSpec.isEmpty() && !spec.forceZk)
            }
            .map { (credential, claimsAndSpec) ->
                val (requestedClaims, spec) = claimsAndSpec
                val document = buildPlainDocuments(
                    request = request,
                    credentialAndRequestedClaims = mapOf(credential to requestedClaims)
                ).single()

                val deviceResponse = DeviceResponse(
                    version = "1.0",
                    documents = arrayOf(document),
                    status = 0U,
                )

                deviceResponse to spec
            }.toMap()
        val zkDocuments = deviceResponsesForZk.map { (deviceResponse, systemSpec) ->
            deviceResponse.documents?.singleOrNull()
                ?: throw IllegalStateException("No or too many documents found!")

            // TODO: redo this, because it might be empty/etc
            val zkSystemSpecs = systemSpec.allowedZkSpec

            val proof = IsoMdocProofRegistry.generate(
                sessionTranscript = request.sessionTranscript,
                deviceResponse = deviceResponse,
                zkSystemSpecs = zkSystemSpecs,
            )

            proof.toZkDocument()
        }
        return zkDocuments
    }

    suspend fun createPlainDocuments(
        request: PresentationRequestParameters,
        credentialAndRequestedClaimsAndSpec: Map<
                SubjectCredentialStore.StoreEntry.Iso,
                Pair<Collection<NormalizedJsonPath>, SystemSpec>
            >,
    ): Collection<Document> {
        return buildPlainDocuments(
            request = request,
            credentialAndRequestedClaims = credentialAndRequestedClaimsAndSpec
                .filter { (_, claimsAndSpec) ->
                    val (_, spec) = claimsAndSpec
                    spec.allowedZkSpec.isEmpty() && !spec.forceZk
                }.mapValues { it.value.first }
        )
    }


    suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaimsAndSpec: Map<
            SubjectCredentialStore.StoreEntry.Iso,
            Pair<Collection<NormalizedJsonPath>, SystemSpec>
        >,
    ): CreatePresentationResult {
        val zkDocuments = createZkDocument(
            request = request,
            credentialAndRequestedClaimsAndSpec = credentialAndRequestedClaimsAndSpec,
        )

        val documents = createPlainDocuments(
            request = request,
            credentialAndRequestedClaimsAndSpec = credentialAndRequestedClaimsAndSpec,
        )


        return CreatePresentationResult.DeviceResponse(
            deviceResponse = DeviceResponse(
                version = "1.0",
                zkDocuments = zkDocuments.toTypedArray().takeIf { it.isNotEmpty() },
                documents = documents.toTypedArray().takeIf { it.isNotEmpty() },
                status = 0U,
            ),
            mdocGeneratedNonce = request.mdocGeneratedNonce
        )

    }


}
@JvmName("toIssuerDisclosed")
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

@JvmName("toDeviceDisclosed")
fun Map<String, DeviceSignedItemList>?.toDisclosed(): Map<String, ZkSignedList>? {
    return this?.mapValues { (_, deviceSignedList) ->
        ZkSignedList(
            entries = deviceSignedList.entries.map { entry ->
                ZkSignedItem(
                    elementIdentifier = entry.key,
                    elementValue = entry.value
                )
            }
        )
    }
}

