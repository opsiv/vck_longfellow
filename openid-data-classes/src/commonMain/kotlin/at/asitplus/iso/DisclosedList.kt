package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper

data class DisclosedList(
    val entries: List<ByteStringWrapper<DisclosedItem>>,
) {

}
