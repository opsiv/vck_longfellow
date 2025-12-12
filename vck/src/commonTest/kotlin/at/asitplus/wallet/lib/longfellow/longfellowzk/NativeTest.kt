package at.asitplus.wallet.lib.longfellow.longfellowzk

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.fromUncompressed
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.longfellow.MdocProof
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.booleans.shouldBeTrue
import kotlin.io.encoding.Base64

val NativeTest by testSuite {
//    "Present and verify" {
//        val docType = "org.iso.18013.5.1.mDL"
//        val timestamp = Clock.System.now()
//        val droBytes = Base64.decode("o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgdgYWE+kaGRpZ2VzdElEAWZyYW5kb21Q5sCMZlguJzRjlUo+Halr7nFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xOGxlbGVtZW50VmFsdWX1amlzc3VlckF1dGiEQ6EBJqBZAX/YGFkBeqZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaIAWCDbj8QqjYWwMWZ+t1YbIB+fbF7NDC6t1tkHJAU4uZO6IgFYIFBPjKvlG+TSoX3HjL1wOR37embmlSQV1G+n7mWoXsNtbWRldmljZUtleUluZm+haWRldmljZUtleaQBAiABIVgg2T42T5nWufGxgLf6+oXcjN28PxZ4RkYWq6kE3zu34XMiWCB8T5XYhh0yuRBaL30S0QnGOBP2uU9Op4nA6hj9VWV4Kmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWxpZGl0eUluZm+jZnNpZ25lZMB0MjAyNC0wMS0zMFQwOTowMDowMFppdmFsaWRGcm9twHQyMDI0LTAxLTMwVDA5OjAwOjAwWmp2YWxpZFVudGlswHQyMDM0LTAxLTMwVDA5OjAwOjAwWlhArEEGvBTkMqNO2iV1n0GeUGgttRVgzsz3CDwW42RX6f9lFvrnyUT0UPzvgtW5h3Dg//pwtO8oumqEtF8jUxqRSmxkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGFghoXFvcmcuaXNvLjE4MDEzLjUuMaFrYWdlX292ZXJfMTj1amRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQKrBIZP0CtRXtPAItqFvDXNeopUZgFXQoeb/B7pE3RW+nHOHDrFNlYK9g+tw2bKwZpPznXHgjuiP0ygRFdpBBL1mc3RhdHVzAA==")
//        val transcriptBytes = Base64.decode("g/b2hHFBbmRyb2lkSGFuZG92ZXJ2MVggLhAFs6nI8N8E20IwAci1OQP+0HG6UCTDuml0DmLUkX5YGWNvbS5hbmRyb2lkLm1kbC5hcHByZWFkZXJYINjnPHBg4+gNPe/CY06wTQjGVuJgaNilY/W5RYXa4U+t")
//        val pkx = Base64.decode("8Yup6TmY5/GB1IHgj77/Mt7GJp5F84hgz2EtXUmmV4o=")
//        val pky = Base64.decode("QnEpNB77mlOkGxlEStzzukQxuhJ2F/WnUO1yDrFDAMg=")
//        val ageOver18Example = RequestedItem(
//            "org.iso.18013.5.1",
//            "age_over_18",
//            byteArrayOf(0xF5.toByte())
//        )
//        val zkSpecSystemId = "longfellow-libzk-v1"
//        val zkSpecCircuitHash = "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
//        val issuerKey = fromUncompressed(ECCurve.SECP_256_R_1, pkx, pky)
//        val attributes = listOf(ageOver18Example)
//
//
//        val proofObj = Proof.generate(
//            circuit = Circuit(zkSpecSystemId, zkSpecCircuitHash),
//            transcript = transcriptBytes,
//            issuerPublicKey = issuerKey,
//            timestamp = timestamp,
//            attributes = attributes,
//            deviceResponseObject = droBytes,
//            docType = docType
//        )
//
//        proofObj.verify().shouldBeTrue()
//    }

    "generate Proof" {
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
        val droSerialized = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xhNgYWFGkaGRpZ2VzdElEAGZyYW5kb21QLnIRybH9KcBTCLqGMFrWZHFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWNNYXjYGFhZpGhkaWdlc3RJRAFmcmFuZG9tULHXcnbhR4DRKxGZZyMOMDRxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlak11c3Rlcm1hbm7YGFhPpGhkaWdlc3RJRAJmcmFuZG9tUDtuSs8mv4UHQY19u2zm9iRxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMThsZWxlbWVudFZhbHVl9dgYWE+kaGRpZ2VzdElEA2ZyYW5kb21Qbwy8PjZ0EBHGjdEKMzolf3FlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8yMWxlbGVtZW50VmFsdWX0amlzc3VlckF1dGiEQ6EBJqBZAejYGFkB46ZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaUAWCCrOG3Qwsxkx7jXf7+EhL1Nqwv+FNd0fyxQZzUrxMBX5gFYIBxOmmfQ8GwainnkUyE1313mCb7oQ18rrqbwUCJ9bq9WAlggrweV/7Cl+zG0Fd6yVpNpgHohuwXPblqF0D95fkVjSo8DWCBxxj8USYzS/NMr1TYxPoA6/LJYzAra7wwC4w82PcSyHgRYIK7wL/KPsLcB3d1YV6w2rfs84pYEIt3bPGfmhy/fLACXbWRldmljZUtleUluZm+haWRldmljZUtleaQBAiABIVggNYPxgK62yo70V2OIuJ+9H1LepfkyQc7nNo8iqWXpzgMiWCBCO8qQ2HTsD1iVcB+ch77JMsTyXS1hORmZ/iDnnWNSkWdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWxpZGl0eUluZm+jZnNpZ25lZMB0MjAyNS0xMS0yM1QxNzowNjozMVppdmFsaWRGcm9twHQyMDI1LTExLTIzVDE3OjA2OjMxWmp2YWxpZFVudGlswHQyMDI2LTExLTIzVDE3OjA2OjMxWlhAK5TqXq/MPhgbLGPJ1gfEhFxNY0lElU5BNdeHV09V2ug+agBUIW/uH++2xiB8++0MHY+igxK8cK73EbXsHzMLxWxkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGFhUoXFvcmcuaXNvLjE4MDEzLjUuMaRqZ2l2ZW5fbmFtZWNNYXhrZmFtaWx5X25hbWVqTXVzdGVybWFubmthZ2Vfb3Zlcl8xOPVrYWdlX292ZXJfMjH0amRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQMQnBrMbr0G7L34WOf0mbUp88VycYYO9vLh0ThaAdmJtl/c0Yu3BIPyWe86hPUlCC9KgT+XXmHnPlgmQss5VIvFmc3RhdHVzAA=="
        val dro = coseCompliantSerializer.decodeFromByteArray(
            DeviceResponse.serializer(),
            Base64.decode(droSerialized)
        )
        val issuerPublicKey = fromUncompressed(
            curve = ECCurve.SECP_256_R_1,
            x = Base64.decode("ZsT1rY9LSwOiy9Mix6WmPEjuy1B7hPWJ5GWGmlHp3mo="),
            y = Base64.decode("SyQC0pMk8yIL0ByB8j8EriMPeWuXK9qfAJVIjESjzZQ=")
        )
        val sessionTranscript = SessionTranscript.forDcApi(
            handover = DCAPIHandover(
                "dcapi",
                "test".encodeToByteArray()
            )
        )

        // TODO check ValidatorMdoc.kt file and implement our own validator
        val prf = shouldNotThrowAny {
            MdocProof.FromMdoc(dro, sessionTranscript, issuerPublicKey)
        }

        shouldNotThrowAny {
            prf.verify().shouldBeTrue()
        }
    }

}
