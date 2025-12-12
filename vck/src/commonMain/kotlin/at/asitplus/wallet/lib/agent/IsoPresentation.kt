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
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.longfellow.Circuit
import at.asitplus.wallet.lib.IsoMdocZk.IsoMdocLongfellowZKProof
import io.github.aakira.napier.Napier
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.time.Clock

object IsoPresentation {
    suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
        credentialQuery: DCQLCredentialQuery? = null,
        // TODO: replace DCQLCredentialQuery with an interface containing a list and a boolean to enforce ZK or not
    ): CreatePresentationResult {
         when(credentialQuery?.format) {
             // TODO: MSO_MDOC should also be able to do zk, but lets solve it via the interface, if the list is nonempty
            CredentialFormatEnum.MSO_MDOC_ZK -> return createLFZKPresentation(
                request = request,
                credentialAndRequestedClaims = credentialAndRequestedClaims,
                credentialQuery = credentialQuery
            )
            else -> return createPlainPresentation(
                request = request,
                credentialAndRequestedClaims = credentialAndRequestedClaims,
                credentialQuery = null
            )
        }
    }

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

    private suspend fun createPlainPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
        credentialQuery: DCQLCredentialQuery?,
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

    suspend fun createLFZKPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
        credentialQuery: DCQLCredentialQuery?
    ): CreatePresentationResult {
        require(request.sessionTranscript != null) {"No or too many documents found!"}

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

        val zkDocuments = deviceResponses.map { deviceResponse ->
            val document = deviceResponse.documents?.singleOrNull()
                ?: throw IllegalStateException("No or too many documents found!")

            val namespaces = document.issuerSigned.namespaces.toDisclosed() ?: emptyMap()
            val attributeCount = namespaces.values.sumOf { it.entries.size }

            // TODO: replace these and set them for each strategy!
            val maxVersion: Int? = null
            val minVersion: Int? = 4
            val system: String = "longfellow-libzk-v1"

            // TODO: differentiate between different zk systems (perhaps using presentation strategy)
            val isoCredentialQuery = credentialQuery as DCQLIsoMdocCredentialQuery
            val zkSystemTypes = isoCredentialQuery.meta.zkSystemType
            val zkSystemType =  zkSystemTypes!!.filter { it.system ==  system }
                .filter { it.numAttributes == attributeCount }
                .filter {minVersion == null || it.version >= minVersion}
                .filter {maxVersion == null || it.version <= maxVersion}
                .maxByOrNull { it.version }
                ?:  throw IllegalStateException("No matching supported zkSystemType!")

            // TODO replace ad-hoch conversion with something more abstract that works for all zk systems
            val zkSystemSpec = ZkSystemSpec(
                system = zkSystemType.system,
                zkSystemId = zkSystemType.system,
                params = mapOf(
                    "circuit_hash" to zkSystemType.circuitHash
                ),
            )

            val proof = IsoMdocLongfellowZKProof.generate(
                sessionTranscript = request.sessionTranscript,
                deviceResponse = deviceResponse,
                zkSystem = zkSystemSpec,
            )

            proof.toZkDocument()
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

