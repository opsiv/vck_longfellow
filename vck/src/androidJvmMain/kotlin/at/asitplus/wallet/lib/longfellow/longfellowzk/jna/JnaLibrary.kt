@file:Suppress("PropertyName", "FunctionName", "LocalVariableName")

package at.asitplus.wallet.lib.longfellow.longfellowzk.jna

import com.sun.jna.Library
import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.Native

private interface IJnaLibrary : Library {
    fun generate_circuit(
        zk_spec_version: Pointer?,
        cb: PointerByReference,
        clen: LongByReference
    ): Int

    fun run_mdoc_prover(
        bcp: ByteArray, bcsz: Long,
        mdoc: ByteArray, mdoc_len: Long,
        pkx: String, pky: String,
        transcript: ByteArray, tr_len: Long,
        attrs: Array<RequestedAttributeStruct>, attrs_len: Long,
        now: String,
        prf: PointerByReference, proof_len: LongByReference,
        zkSpec: Pointer?
    ): Int

    fun run_mdoc_verifier(
        bcp: ByteArray, bcsz: Long,
        pkx: String, pky: String,
        transcript: ByteArray, tr_len: Long,
        attrs: Array<RequestedAttributeStruct>, attrs_len: Long,
        now: String,
        prf: ByteArray, proof_len: Long,
        doc_type: String,
        zkSpec: Pointer?
    ): Int

    fun find_zk_spec(system_name: String, circuit_hash: String): Pointer?
}

private fun getJNaLibraryPath(): String {
    val defaultName = "longfellow_mdoc"
    val isAndroid = System.getProperty("java.vendor")?.lowercase()?.contains("android") == true
    if (isAndroid) return defaultName

    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val suffix = when {
        os.contains("mac") || os.contains("darwin") -> "dylib"
        os.contains("win") -> "dll"
        else -> "so"
    }
    return "/native/${os}-${arch}/${defaultName}.${suffix}"
}

object JnaLibrary : IJnaLibrary by Native.load(
    getJNaLibraryPath(),
    IJnaLibrary::class.java
)
