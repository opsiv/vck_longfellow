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
import kotlin.collections.component1
import kotlin.collections.component2

object IsoPresentation {

    // TODO: this functions feels out of place here, since it it also used in [IsoMdocLongfellowZkProof.kt]
    internal suspend fun buildPlainDocument(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>
    ): Document {
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

        return Document(
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

    suspend fun createZkDocuments(request: PresentationRequestParameters,
                                  credentialsAndMeta: Map<SubjectCredentialStore.StoreEntry.Iso, IsoPresentationMeta>,
    ): Map<SubjectCredentialStore.StoreEntry.Iso, ZkDocument> {
        require(request.sessionTranscript != null) {"No or too many documents found!"}
        val zkCompatibleCredentialsAndMeta = credentialsAndMeta
            .filter { (_, meta) -> !(meta.spec.allowedZkSpec.isEmpty() && !meta.spec.forceZk) }

        return zkCompatibleCredentialsAndMeta.mapValues {
            // TODO: allow soft fail in order to fall back to PlainDocuments
            IsoMdocProofRegistry.generate(
                request = request,
                credentialAndMeta = it
            ).toZkDocument()
        }
    }

    suspend fun createPlainDocuments(
        request: PresentationRequestParameters,
        credentialsAndMeta: Map<SubjectCredentialStore.StoreEntry.Iso, IsoPresentationMeta>,
    ): Map<SubjectCredentialStore.StoreEntry.Iso, Document> = credentialsAndMeta
        .filter { (_, meta) -> !meta.spec.forceZk }
        .mapValues { it.value.claims }
        .mapValues { (credential, requestedClaims) ->
            buildPlainDocument(request, credential, requestedClaims)
        }


    suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialsAndMeta: Map<
            SubjectCredentialStore.StoreEntry.Iso,
            IsoPresentationMeta
        >,
    ): CreatePresentationResult {
        var remainingCredentials = credentialsAndMeta

        val credentialAndZkDocuments = createZkDocuments(
            request = request,
            credentialsAndMeta = remainingCredentials,
        )
        remainingCredentials = remainingCredentials.filterKeys {
            it !in credentialAndZkDocuments.keys
        }

        // only take the remaining documents to create plain documents
        val credentialAndDocuments = createPlainDocuments(
            request = request,
            credentialsAndMeta = remainingCredentials,
        )
        remainingCredentials = remainingCredentials.filterKeys {
            it !in credentialAndDocuments.keys
        }

        val zkDocuments =  credentialAndZkDocuments.values.toTypedArray().takeIf { it.isNotEmpty() }
        val documents = credentialAndDocuments.values.toTypedArray().takeIf { it.isNotEmpty() }

        require(remainingCredentials.isEmpty()) { "Not all credentials have been successfully created!" }

        return CreatePresentationResult.DeviceResponse(
            deviceResponse = DeviceResponse(
                version = "1.0",
                zkDocuments = zkDocuments,
                documents = documents,
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

