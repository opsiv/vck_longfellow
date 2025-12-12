package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec

interface IsoMdocZkProofFactory {
    fun supports(zkSystemSpec: ZkSystemSpec): Boolean

    fun generate(
        zkSystemSpec: ZkSystemSpec,
        sessionTranscript: SessionTranscript,
        deviceResponse: DeviceResponse
    ): IsoMdocZkProof

    fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): IsoMdocZkProof
}


