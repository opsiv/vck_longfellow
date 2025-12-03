package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName

data class DisclosedItem(
    @SerialName(PROP_ELEMENT_ID)
    val elementIdentifier: String,

    @SerialName(PROP_ELEMENT_VALUE)
    val elementValue: Any,
) {
    override fun toString(): String = "IssuerSignedItem(elementIdentifier='$elementIdentifier'," +
            " elementValue=${elementValue.toCustomString()})"

    companion object {
        internal const val PROP_ELEMENT_ID = "elementIdentifier"
        internal const val PROP_ELEMENT_VALUE = "elementValue"
    }
}

private fun Any.toCustomString(): String = when (this) {
    is ByteArray -> this.encodeToString(Base16Strict)
    is Array<*> -> this.contentDeepToString()
    else -> this.toString()
}