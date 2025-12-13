package at.asitplus.wallet.lib.data

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSignedItem
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

data class IsoZkDocumentParsed(
    val zkDocument: ZkDocument,
    override val validItems: List<ZkSignedItem> = listOf(),
    override val invalidItems: List<ZkSignedItem> = listOf(),
    override val freshnessSummary: CredentialFreshnessSummary.Mdoc // TODO: possibly do an extra class for MdocZk
) : IsoDocumentParsed
