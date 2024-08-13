package de.rub.nds.sshstatelearner.sul.response

import de.rub.nds.tlsattacker.transport.socket.SocketState
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class ResponseFingerprintTest {

    @Test
    fun testHashCode() {
        val fingerprintEmptyMessageAndClosedMessage = ResponseFingerprint(listOf(), SocketState.CLOSED)
        val fingerprintEmptyMessageAndOpenMessage = ResponseFingerprint(listOf(), SocketState.UP)
        Assertions.assertFalse(fingerprintEmptyMessageAndOpenMessage == fingerprintEmptyMessageAndClosedMessage)
    }

    @Test
    fun testHashCode2() {
        val fingerprintEmptyMessageAndClosedMessage = ResponseFingerprint(listOf(), SocketState.UP)
        val fingerprintEmptyMessageAndOpenMessage = ResponseFingerprint(listOf(), SocketState.UP)
        Assertions.assertTrue(fingerprintEmptyMessageAndOpenMessage == fingerprintEmptyMessageAndClosedMessage)
    }

    @Test
    fun testHashCode3() {
        val fingerprintEmptyMessageAndClosedMessage = ResponseFingerprint(listOf(), SocketState.CLOSED)
        val fingerprintEmptyMessageAndOpenMessage = ResponseFingerprint(listOf(), SocketState.CLOSED)
        Assertions.assertTrue(fingerprintEmptyMessageAndOpenMessage == fingerprintEmptyMessageAndClosedMessage)
    }
}