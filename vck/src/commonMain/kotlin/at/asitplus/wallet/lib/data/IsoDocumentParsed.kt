package at.asitplus.wallet.lib.data

import at.asitplus.iso.Item
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

interface IsoDocumentParsed {
    val validItems: List<Item>
    val invalidItems: List<Item>
    val freshnessSummary: CredentialFreshnessSummary.Mdoc
}
