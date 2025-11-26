package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.ResponseItem
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.cbor.publicKey
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SdJwtConstants.NAME_SD
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.longfellow.AnySerializer
import at.asitplus.wallet.lib.longfellow.Circuit
import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import at.asitplus.wallet.lib.longfellow.truncateToSecond
import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.time.Clock

class VerifiablePresentationFactory(
    private val keyMaterial: KeyMaterial,
    private val signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signKeyBinding: SignJwtFun<KeyBindingJws> =
        SignJwt(keyMaterial, JwsHeaderNone()),
) {

    suspend fun createVerifiablePresentationForIsoCredentials(
        request: PresentationRequestParameters,
        credentialAndDisclosedAttributes: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): KmmResult<CreatePresentationResult> = catching {
        createIsoPresentation(
            request = request,
            credentialAndRequestedClaims = credentialAndDisclosedAttributes,
        )
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: Collection<NormalizedJsonPath>,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> createVcPresentation(
                request = request,
                validCredentials = listOf(credential),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = disclosedAttributes,
            )

            is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                request = request,
                credentialAndRequestedClaims = mapOf(credential to disclosedAttributes),
            )
        }
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: DCQLCredentialQueryMatchingResult,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> if (disclosedAttributes !is DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) {
                throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
            } else createVcPresentation(
                request = request,
                validCredentials = listOf(credential),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = when (disclosedAttributes) {
                    DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult -> credential.disclosures.entries.map {
                        NormalizedJsonPath() + it.value!!.claimName!!
                    }

                    is DCQLCredentialQueryMatchingResult.ClaimsQueryResults -> disclosedAttributes.claimsQueryResults.map {
                        it as DCQLClaimsQueryResult.JsonResult
                    }.map {
                        it.nodeList.map {
                            it.normalizedJsonPath
                        }
                    }.flatten()
                },
            )

            is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                request = request,
                credentialAndRequestedClaims = mapOf(credential to disclosedAttributes.toRequestedIsoClaims(credential)),
            )
        }
    }

    private fun DCQLCredentialQueryMatchingResult.toRequestedIsoClaims(
        credential: SubjectCredentialStore.StoreEntry.Iso,
    ) = when (this) {
        DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult -> credential.issuerSigned.namespaces!!.entries.flatMap { namespace ->
            namespace.value.entries.map {
                NormalizedJsonPath() + namespace.key + it.value.elementIdentifier
            }
        }

        is DCQLCredentialQueryMatchingResult.ClaimsQueryResults -> claimsQueryResults.map {
            it as DCQLClaimsQueryResult.IsoMdocResult
        }.map {
            NormalizedJsonPath() + it.namespace + it.claimName
        }
    }

    private suspend fun createZkIsoPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): CreatePresentationResult.MdocProof {
        val (deviceResponse: DeviceResponse, mdocGeneratedNonce: String?) = createIsoPresentation(
            request = request,
            credentialAndRequestedClaims = credentialAndRequestedClaims,
        )
        // TODO: ensure only one doctype and only one namespace exists (LF cant handle more than that)
        val document: Document = deviceResponse.documents?.single()
            ?: throw IllegalStateException("No or too many documents found!")

        // TODO: mdocGeneratedNonce to SessionTranscript (i think more or less done)
        //  Check if sessionTranscript empty and error out if so. comapre with what is done if the request.calcIsoDeviceSignaturePlain.invoke() was empty i guess
        val sessionTranscript: SessionTranscript = request.calcSessionTranscript()
            ?: throw IllegalStateException("No Session Transcript found!")

        // TODO: get issuer-pk from somewhere (i think done, but need to reevaluate if there is a better place)
        val issuerPublicKey: CryptoPublicKey.EC = document
            .issuerSigned.issuerAuth
            .unprotectedHeader?.publicKey
            ?.toCryptoPublicKey()?.getOrNull() as? CryptoPublicKey.EC
            ?: throw IllegalStateException("No Issuer Public Key found in credential!")

        // TODO: deviceResponse and SessionTranscript to iso/ModcProof (keep in mind timestamp needs seconds precision -> truncate)
        val now = Clock.System.now().truncateToSecond()

        // TODO: i dont like the current version of anyserializer. i should fix this for sth more generic.
        //  Longterm, we dont want to serialize here at all yet (cborValue should just be value here)
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
        val circuit = Circuit.forResponseItems(attributes.size)
        val rawProof = NativeLibrary.generateProof(
            circuit.raw, droBytes,
            issuerPublicKey, transcriptBytes, now, attributes,
            circuit.handle).getOrThrow()

        // TODO: think about what to return. is the mdoc generated nonce enough fpr the verifier to be able to verify?
        //  Find out how this is done in the standard verification process (non LF) and just do it exactly like that

       return CreatePresentationResult.MdocProof(
           mdocProof = at.asitplus.iso.MdocProof(
               proof = rawProof,
               timestamp = now,
               attributes = attributes,
               doctype = document.docType
           ),
           mdocGeneratedNonce = mdocGeneratedNonce
       )

    }

    private suspend fun createIsoPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): CreatePresentationResult.DeviceResponse {
        Napier.d("createIsoPresentation with $request and $credentialAndRequestedClaims")

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
        return CreatePresentationResult.DeviceResponse(
            deviceResponse = DeviceResponse(
                version = "1.0",
                documents = documents.toTypedArray(),
                status = 0U,
            ),
            mdocGeneratedNonce = request.mdocGeneratedNonce
        )
    }

    private suspend fun createSdJwtPresentation(
        request: PresentationRequestParameters,
        validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
        requestedClaims: Collection<NormalizedJsonPath>,
    ): CreatePresentationResult.SdJwt {
        // TODO: this feels wrong, each path should represent a single attribute to be disclosed
        val nameSegments = requestedClaims
            .flatMap { it.segments }
            .filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
        // All disclosures as requested by claim name
        val disclosuresByName = nameSegments
            .mapNotNull { claim ->
                validSdJwtCredential.disclosures.entries.firstOrNull { it.value?.claimName == claim.memberName }
            }.toSet()
        // Inner disclosures when an object has been requested by name (above), but contains more _sd entries
        val innerDisclosures = validSdJwtCredential.disclosures.entries.filter { claim ->
            val digest = validSdJwtCredential.sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
            claim.asHashedDisclosure(digest)?.let { hashedDisclosure ->
                disclosuresByName.any { it.containsHashedDisclosure(hashedDisclosure) }
            } == true
        }
        val allDisclosures = (disclosuresByName.map { it.key } + innerDisclosures.map { it.key }).toSet()

        val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, allDisclosures)
        val keyBinding = createKeyBindingJws(request, issuerJwtPlusDisclosures)
        val issuerSignedJwsSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
        val issuerSignedJws =
            JwsSigned.deserialize(JsonElement.serializer(), issuerSignedJwsSerialized, vckJsonSerializer)
                .getOrElse { throw PresentationException(it) }
        val sdJwt = SdJwtSigned.presented(issuerSignedJws, allDisclosures, keyBinding)
        return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
    }

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asHashedDisclosure(digest: Digest): String? =
        value?.toDisclosure()?.hashDisclosure(digest)

    private fun Map.Entry<String, SelectiveDisclosureItem?>.containsHashedDisclosure(hashDisclosure: String): Boolean =
        asJsonObject()?.sdElements()?.strings()?.any { it == hashDisclosure } == true

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asJsonObject(): JsonObject? =
        (value?.claimValue as? JsonObject?)

    private fun JsonObject.sdElements(): JsonArray? = (get(NAME_SD) as? JsonArray?)

    private fun JsonArray.strings(): List<String> = mapNotNull { (it as? JsonPrimitive?)?.content }

    private suspend fun createKeyBindingJws(
        request: PresentationRequestParameters,
        issuerJwtPlusDisclosures: String,
    ): JwsSigned<KeyBindingJws> = signKeyBinding(
        JwsContentTypeConstants.KB_JWT,
        KeyBindingJws(
            issuedAt = Clock.System.now(),
            audience = request.audience,
            challenge = request.nonce,
            sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
            transactionDataHashes = request.transactionData?.hash(request.transactionDataHashesAlgorithm),
            transactionDataHashesAlgorithmString = request.transactionDataHashesAlgorithm?.toIanaName(),
        ),
        KeyBindingJws.serializer(),
    ).getOrElse {
        throw PresentationException(it)
    }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    suspend fun createVcPresentation(
        validCredentials: List<SubjectCredentialStore.StoreEntry.Vc>,
        request: PresentationRequestParameters,
    ): CreatePresentationResult.Signed = with(
        signVerifiablePresentation(
            JwsContentTypeConstants.JWT,
            VerifiablePresentation(validCredentials.map { it.vcSerialized }).toJws(
                request.nonce,
                validCredentials.map { it.vc.vc.credentialSubject.id }.first(),
                request.audience
            ),
            VerifiablePresentationJws.serializer(),
        ).getOrElse {
            throw PresentationException(it)
        }) {
        CreatePresentationResult.Signed(serialize(), this)
    }
}
