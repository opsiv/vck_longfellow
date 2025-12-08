package at.asitplus.wallet.lib.data

import at.asitplus.dif.*
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.agent.PresentationExchangeCredentialDisclosure
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = CredentialPresentationRequestSerializer::class)
sealed interface CredentialPresentationRequest {

    fun toCredentialPresentation(): CredentialPresentation

    @Serializable
    data class PresentationExchangeRequest(
        val presentationDefinition: PresentationDefinition,
        val fallbackFormatHolder: FormatHolder? = null,
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation() = toCredentialPresentation(null)

        fun toCredentialPresentation(
            inputDescriptorSubmissions: Map<String, PresentationExchangeCredentialDisclosure>?
        ): CredentialPresentation = CredentialPresentation.PresentationExchangePresentation(
            presentationRequest = this,
            inputDescriptorSubmissions = inputDescriptorSubmissions
        )

        companion object {
            fun forAttributeNames(vararg attributeName: String) = PresentationExchangeRequest(
                PresentationDefinition(
                    DifInputDescriptor(
                        Constraint(
                            fields = attributeName.map { ConstraintField(path = listOf(it)) }
                        )
                    )
                ),
            )
        }
    }

    @Serializable
    @JvmInline
    value class DCQLRequest(
        val dcqlQuery: DCQLQuery
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation() = toCredentialPresentation(null)

        // TODO: I think we need to tackle this instead of request, because i think that here we have got a mapping!
        //  - wait we already have presentationRequest (this) and we have a mapping to the creqentialQuerySubmissions!
        //  - Anyway I think it should happen here and not in
        fun toCredentialPresentation(
            credentialQuerySubmissions: Map<DCQLCredentialQueryIdentifier, DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>?
        ): CredentialPresentation = CredentialPresentation.DCQLPresentation(
            presentationRequest = this,
            credentialQuerySubmissions = credentialQuerySubmissions
        )
    }
}