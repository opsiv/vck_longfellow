package at.asitplus.iso

import kotlinx.serialization.Serializable

@Serializable
data class ResponseItem(
    val nameSpaceId: String,
    val id: String,
    val cborValue: ByteArray,
) {


    init {
        require(nameSpaceId.length <= NAME_SPACE_ID_SIZE) {
            "nameSpaceId too long"
        }
        require(id.length <= ID_SIZE) {
            "id too long"
        }
        require(cborValue.size <= CBOR_VALUE_SIZE) {
            "cborValue too long"
        }
    }

    companion object {
        const val NAME_SPACE_ID_SIZE = 64
        const val ID_SIZE = 32
        const val CBOR_VALUE_SIZE = 64

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ResponseItem

        if (nameSpaceId != other.nameSpaceId) return false
        if (id != other.id) return false
        if (!cborValue.contentEquals(other.cborValue)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nameSpaceId.hashCode()
        result = 31 * result + id.hashCode()
        result = 31 * result + cborValue.contentHashCode()
        return result
    }
    // TODO: somewhere else i already wrote that we shouldnt cbor encode here. but can we instead just use IsoMdocResult class?
}
