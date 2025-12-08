package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLIsoMdocCredentialQuery(
    @SerialName(DCQLCredentialQuery.SerialNames.ID)
    override val id: DCQLCredentialQueryIdentifier,
    @SerialName(DCQLCredentialQuery.SerialNames.FORMAT)
    override val format: CredentialFormatEnum,
    @SerialName(DCQLCredentialQuery.SerialNames.META)
    override val meta: DCQLIsoMdocCredentialMetadataAndValidityConstraints,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIMS)
    override val claims: DCQLClaimsQueryList<DCQLIsoMdocClaimsQuery>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIM_SETS)
    override val claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.MULTIPLE)
    override val multiple: Boolean? = false,
    @SerialName(DCQLCredentialQuery.SerialNames.TRUSTED_AUTHORITIES)
    override val trustedAuthorities: List<String>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING)
    override val requireCryptographicHolderBinding: Boolean? = true,
) : DCQLCredentialQuery {
    init {
        validate(this)
    }

    companion object {
        private val validCredentialFormats = setOf(
            CredentialFormatEnum.MSO_MDOC,
            CredentialFormatEnum.MSO_MDOC_ZK
        )

        fun validate(query: DCQLIsoMdocCredentialQuery) = query.run {
            DCQLCredentialQuery.validate(this)
            if (format !in validCredentialFormats) {
                throw IllegalArgumentException("Value has an invalid format identifier in this context.")
            }
            if (format == CredentialFormatEnum.MSO_MDOC_ZK && meta.zkSystemType == null) {
                throw IllegalArgumentException("No acceptable zero knowledge system types provided.")
            }

        }
    }
}