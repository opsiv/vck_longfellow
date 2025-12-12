package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec

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
    //  for example if the number of attributes is releavnt, or the existence of a DeviceSigned namespaces
    private fun findFactory(spec: ZkSystemSpec): IsoMdocZkProofFactory =
        factories.firstOrNull { it.supports(spec) }
            ?: error("Unsupported zkSystemSpec: $spec")

    fun generate(zkSystemSpec: ZkSystemSpec, sessionTranscript: SessionTranscript, deviceResponse: DeviceResponse): IsoMdocZkProof =
        findFactory(zkSystemSpec).generate(zkSystemSpec, sessionTranscript, deviceResponse)

    fun load(zkDocument: ZkDocument, sessionTranscript: SessionTranscript, zkSystemSpec: ZkSystemSpec): IsoMdocZkProof =
        findFactory(zkSystemSpec).load(zkDocument, sessionTranscript, zkSystemSpec)
}