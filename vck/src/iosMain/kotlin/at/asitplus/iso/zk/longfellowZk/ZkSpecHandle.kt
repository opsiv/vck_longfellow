package at.asitplus.iso.zk.longfellowzk


import at.asitplus.signum.longfellow.src.iosMain.cinterop.ZkSpecStruct
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class)
actual class ZkSpecHandle private constructor(
    val ptr: CPointer<ZkSpecStruct>
) {
    companion object {
        internal fun toZkSpecHandle(ptr: CPointer<ZkSpecStruct>?): ZkSpecHandle? {
          return ptr?.let { return ZkSpecHandle(it) }
        }
    }
}
