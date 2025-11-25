package at.asitplus.wallet.lib.agent

import at.asitplus.dif.ZkSystemSpec
import at.asitplus.iso.DeviceResponse
import at.asitplus.wallet.lib.data.ZkProofResponse

interface ZkProofAlgorithm {
    suspend fun createProof(
        deviceResponse: DeviceResponse,
        zkSystemSpec: ZkSystemSpec,
    ): ByteArray

    suspend fun verifyProof(
        zkSystemSpec: ZkSystemSpec,
        zkProofResponse: ZkProofResponse,
        challenge: String // build Session transcript form it
    )
}