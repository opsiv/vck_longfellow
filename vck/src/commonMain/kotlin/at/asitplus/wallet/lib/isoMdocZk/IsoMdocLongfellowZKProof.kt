package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.isoMdocZk.IsoMdocLongfellowZkProofFactory.Companion.buildParams
import at.asitplus.wallet.lib.isoMdocZk.IsoMdocLongfellowZkProofFactory.Companion.extractIssuerKey
import at.asitplus.wallet.lib.isoMdocZk.IsoMdocLongfellowZkProofFactory.Companion.supports
import at.asitplus.wallet.lib.longfellow.LongfellowZkParams
import at.asitplus.wallet.lib.longfellow.longfellowzk.backend.LongfellowZkBackend
import at.asitplus.wallet.lib.longfellow.longfellowzk.RequestedItem
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.time.Instant

internal class IsoMdocLongfellowZKProof private constructor(
    override val zkSystemSpec: ZkSystemSpec,
    override val timestamp: Instant,
    override val issuerZkSignedNamespaces: Map<String, ZkSignedList>,
    override val deviceZkSignedNamespaces: Map<String, ZkSignedList>,
    override val rawProof: ByteArray,
    override val docType: String,
    override val msoX5Chain: List<ByteArray>?,
    private val issuerKey: CryptoPublicKey.EC,
    private val zkParams: LongfellowZkParams,
    private val sessionTranscriptBytes: ByteArray,
    private val backend: LongfellowZkBackend
) : IsoMdocZkProof() {

    override fun verify(): Boolean {
        val requestedItems = issuerZkSignedNamespaces.toRequestedItems()
        if (!requestedItems.all { it.isValid() }) return false

        val (issuerKeyX, issuerKeyY) = issuerKey.toPrefixedHexString()
        val encodedTimestamp = timestamp.toIso8061()

        return backend.verifyProof(
            circuit = zkParams.circuit,
            publicKeyX = issuerKeyX,
            publicKeyY = issuerKeyY,
            transcript = sessionTranscriptBytes,
            requestedItems = requestedItems,
            timestamp = encodedTimestamp,
            proof = rawProof,
            docType = docType,
            zkSpec = zkParams.handle
        ).getOrThrow()
    }

    companion object {
        fun create(
            zkSystemSpec: ZkSystemSpec,
            timestamp: Instant,
            issuerZkSignedNamespaces: Map<String, ZkSignedList>,
            deviceZkSignedNamespaces: Map<String, ZkSignedList>,
            rawProof: ByteArray,
            docType: String,
            msoX5Chain: List<ByteArray>?,
            sessionTranscriptBytes: ByteArray,
            backend: LongfellowZkBackend
        ): IsoMdocLongfellowZKProof {
            validateSystem(zkSystemSpec)
            val issuerKey = extractIssuerKey(msoX5Chain)
            val params = buildParams(zkSystemSpec)

            return IsoMdocLongfellowZKProof(
                zkSystemSpec = zkSystemSpec,
                timestamp = timestamp,
                issuerZkSignedNamespaces = issuerZkSignedNamespaces,
                deviceZkSignedNamespaces = deviceZkSignedNamespaces,
                rawProof = rawProof,
                docType = docType,
                msoX5Chain = msoX5Chain,
                issuerKey = issuerKey,
                zkParams = params,
                sessionTranscriptBytes = sessionTranscriptBytes,
                backend = backend
            )
        }
        internal fun validateSystem(zkSystemSpec: ZkSystemSpec) {
            require(supports(zkSystemSpec)) {
                "Incompatible ZkSystem, ${zkSystemSpec.system}"
            }
        }
    }
}


internal fun Map<String, ZkSignedList>.toRequestedItems() = flatMap { (namespace, itemList) ->
    itemList.entries.map { item ->
        RequestedItem(namespace, item.elementIdentifier, item.elementValue)
    }
}

internal fun Instant.toIso8061(): String {
    require(this.nanosecondsOfSecond == 0) { "Instance of 'Instant' is not ISO 8061 compatible" }
    // TODO: Review use of UTC-SLS vs UTC
    return this.toString()
}

private fun ModularBigInteger.toPrefixedHexString() = "0x${this.toString(16)}"
internal fun CryptoPublicKey.EC.toPrefixedHexString() = this.x.toPrefixedHexString() to this.y.toPrefixedHexString()