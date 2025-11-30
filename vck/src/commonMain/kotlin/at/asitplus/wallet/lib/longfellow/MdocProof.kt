package at.asitplus.wallet.lib.longfellow

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.SessionTranscript
import at.asitplus.signum.indispensable.CryptoPublicKey
import kotlin.time.Instant
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.ResponseItem
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.longfellow.longfellowzk.NativeLibrary
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

interface MdocProof {
    fun verify(): Boolean
    val circuit: Circuit
    val issuerPublicKey: CryptoPublicKey.EC
    val timestamp: Instant
    val docType: String
    val attributes: List<ResponseItem>
    val transcript: SessionTranscript
    val rawProof: ByteArray

    data class Presentation (
        val circuit: Circuit,
        val transcript: SessionTranscript,
        val issuerPublicKey: CryptoPublicKey.EC,
        val timestamp: Instant,
        val attributes: List<ResponseItem>,
        val rawProof: ByteArray,
        val docType: String
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Presentation

            if (circuit != other.circuit) return false
            if (transcript != other.transcript) return false
            if (issuerPublicKey != other.issuerPublicKey) return false
            if (timestamp != other.timestamp) return false
            if (attributes != other.attributes) return false
            if (!rawProof.contentEquals(other.rawProof)) return false
            if (docType != other.docType) return false

            return true
        }

        override fun hashCode(): Int {
            var result = circuit.hashCode()
            result = 31 * result + transcript.hashCode()
            result = 31 * result + issuerPublicKey.hashCode()
            result = 31 * result + timestamp.hashCode()
            result = 31 * result + attributes.hashCode()
            result = 31 * result + rawProof.contentHashCode()
            result = 31 * result + docType.hashCode()
            return result
        }
    }

    class FromMdoc (
        val deviceResponse: DeviceResponse,
        override val transcript: SessionTranscript,
        override val issuerPublicKey: CryptoPublicKey.EC
    ): MdocProof {

        override fun verify(): Boolean = NativeLibrary.verifyProof(
            circuit.raw, issuerPublicKey, transcriptBytes, attributes,
            timestamp, rawProof, docType, circuit.handle
        ).getOrThrow()

        init {
            if (deviceResponse.documents == null) {
                throw IllegalArgumentException("Device response document cannot be null")
            }
            if (deviceResponse.documents!!.size != 1) {
                throw IllegalArgumentException("Device response document cannot have exactly one document")
            }
            // TODO check the rest!
            // - Maybe only 1 namespace for now?
            // - use requirenotnull syntactic sugar
        }

        override val timestamp: Instant = Clock.System.now().truncateToSecond()
        private val document: Document = deviceResponse.documents!!.single()
        override val docType: String = document.docType

        override val attributes: List<ResponseItem> = mutableListOf<ResponseItem>().apply {
            val issuedNameSpaces = document.issuerSigned.namespaces
            issuedNameSpaces?.entries?.forEach { (nameSpaceId, issuerSignedList) ->
                issuerSignedList.entries.forEach { item ->
                    add(ResponseItem(nameSpaceId, item.value.elementIdentifier, item.value.elementValue))
                }
            }
        }



        private val transcriptBytes = coseCompliantSerializer.encodeToByteArray(transcript)
        private val droBytes = coseCompliantSerializer.encodeToByteArray(deviceResponse)

        override val rawProof: ByteArray by lazy {
            NativeLibrary.generateProof(
                circuit.raw, droBytes,
                issuerPublicKey, transcriptBytes, timestamp, attributes,
                circuit.handle).getOrThrow()
        }

        override val circuit = Circuit.forResponseItems(attributes.size)

        // TODO: https://github.com/google/longfellow-zk/blob/main/docs/content/en/docs/zk-system-spec.md
        // - make proof a data class
        // - make circuit a data class based on the zk_spec (at least think about it)
    }

}

@OptIn(ExperimentalTime::class)
fun Instant.truncateToSecond(): Instant =
    Instant.fromEpochSeconds(this.epochSeconds)