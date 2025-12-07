package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.data.NonEmptyList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Extended ISO Mdoc metadata with Longfellow ZK support
 * See https://github.com/google/longfellow-zk/blob/main/docs/content/en/docs/zk-system-spec.md
 */
@Serializable
data class DCQLIsoMdocZkCredentialMetadataAndValidityConstraints(
    @SerialName(SerialNames.DOCTYPE_VALUE)
    val doctypeValue: String,

    @SerialName(SerialNames.ZK_SYSTEM_TYPE)
    val zkSystemType: NonEmptyList<DCQLZkSystemType>,

    @SerialName(SerialNames.VERIFIER_MESSAGE)
    val verifierMessage: String? = null,
) : DCQLCredentialMetadataAndValidityConstraints {
    object SerialNames {
        const val DOCTYPE_VALUE = "doctype_value"
        const val ZK_SYSTEM_TYPE = "zk_system_type"
        const val VERIFIER_MESSAGE = "verifier_message"
    }

    fun validate(actualDoctypeValue: String?): KmmResult<Unit> = catching {
        if (actualDoctypeValue != doctypeValue)
            throw IllegalStateException("Unsupported credential format")
    }
}
