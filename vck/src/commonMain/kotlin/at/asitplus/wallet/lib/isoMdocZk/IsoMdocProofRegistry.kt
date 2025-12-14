package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore

// TODO: for now we just use the first fitting IsoMdocZk class and run with it. In future revision, we might have
//  several candidates, and some might even fail while other wouldn't. so it could be wise to try the other ones,
//  if one fails for unexpected reasons
object IsoMdocProofRegistry {
    private val factories = mutableListOf<IsoMdocZkProofFactory>()

    init {
        // TODO: rethink autoregistering
        register(IsoMdocLongfellowZKProof.Factory)
    }

    fun register(factory: IsoMdocZkProofFactory) {
        factories += factory
    }


    // TODO: consider giving even more options to findFactory, a document or zkDocument could be relevant,
    //  for example if the number of attributes is relevant, or the existence of a DeviceSigned namespaces
    private fun findFactory(zkSystemSpecs: List<ZkSystemSpec>): Pair<IsoMdocZkProofFactory, ZkSystemSpec> {
        zkSystemSpecs.forEach { zkSystemSpec ->
            factories.firstOrNull { it.supports(zkSystemSpec) }
                ?.let { return it to zkSystemSpec}
        }
        error("Unsupported zkSystemSpecs: $zkSystemSpecs")
    }


    suspend fun generate(
        request: PresentationRequestParameters,
        credentialAndRequestedClaimsAndSpec: Map.Entry<
            SubjectCredentialStore.StoreEntry.Iso,
            Pair<Collection<NormalizedJsonPath>, SystemSpec>
        >): IsoMdocZkProof {
        val credential = credentialAndRequestedClaimsAndSpec.key
        val (requestedClaims, systemSpec) = credentialAndRequestedClaimsAndSpec.value
        val (isoMdocZkProofFactory, zkSystemSpec) = findFactory(systemSpec.allowedZkSpec)
        return isoMdocZkProofFactory.generate(request, credential, requestedClaims, zkSystemSpec)
    }

    // TODO: unfortunately we only have the sessionTranscript here instead of all of the PresentationRequestParameters,
    //  check if that is somehow still possible to have a more consistent interface for generate and load
    fun load(zkSystemSpecs: List<ZkSystemSpec>, zkDocument: ZkDocument, sessionTranscript: SessionTranscript): IsoMdocZkProof {
        val (isoMdocZkProofFactory, zkSystemSpec) = findFactory(zkSystemSpecs)
        return isoMdocZkProofFactory.load(zkDocument, sessionTranscript, zkSystemSpec)
    }

}