package at.asitplus.iso

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable


@Serializable
data class ResponseItem(
    val nameSpaceId: String,
    val id: String,
    @Contextual
    val value: Any,
) {
    init {
        require(nameSpaceId.length <= NAME_SPACE_ID_SIZE) {
            "nameSpaceId too long"
        }
        require(id.length <= ID_SIZE) {
            "id too long"
        }
    }

    companion object {
        const val NAME_SPACE_ID_SIZE = 64
        const val ID_SIZE = 32
        const val CBOR_VALUE_SIZE = 64

        internal const val PROP_NAMESPACE_ID = "nameSpaceId"
        internal const val PROP_ID = "id"
        internal const val PROP_VALUE = "value"

    }
    // TODO: can we instead just use IsoMdocResult class?
}
