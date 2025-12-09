package at.asitplus.wallet.lib.data

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSignedItem
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.longfellow.Proof

data class IsoZkDocumentParsed(
    val zkDocument: ZkDocument,
    val validItems: List<ZkSignedItem> = listOf(),
    val invalidItems: List<ZkSignedItem> = listOf(),
    val freshnessSummary: CredentialFreshnessSummary.Mdoc // TODO: possibly do an extra class for MdocZk
)
