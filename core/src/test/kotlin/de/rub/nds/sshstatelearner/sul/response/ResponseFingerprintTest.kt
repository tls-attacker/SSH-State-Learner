package de.rub.nds.sshstatelearner.sul.response

import de.rub.nds.tlsattacker.transport.socket.SocketState
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class ResponseFingerprintTest {

    @Test
    fun testHashCode() {
        val fingerprintEmptyMessageAndClosedMessage = ResponseFingerprint(listOf(), SocketState.CLOSED, false)
        val fingerprintEmptyMessageAndOpenMessage = ResponseFingerprint(listOf(), SocketState.UP, false)
        Assertions.assertFalse(fingerprintEmptyMessageAndOpenMessage == fingerprintEmptyMessageAndClosedMessage)
    }

    @Test
    fun testHashCode2() {
        val fingerprintEmptyMessageAndClosedMessage = ResponseFingerprint(listOf(), SocketState.UP, false)
        val fingerprintEmptyMessageAndOpenMessage = ResponseFingerprint(listOf(), SocketState.UP, false)
        Assertions.assertTrue(fingerprintEmptyMessageAndOpenMessage == fingerprintEmptyMessageAndClosedMessage)
    }

    @Test
    fun testHashCode3() {
        val fingerprintEmptyMessageAndClosedMessage = ResponseFingerprint(listOf(), SocketState.CLOSED, false)
        val fingerprintEmptyMessageAndOpenMessage = ResponseFingerprint(listOf(), SocketState.CLOSED, false)
        Assertions.assertTrue(fingerprintEmptyMessageAndOpenMessage == fingerprintEmptyMessageAndClosedMessage)
    }
}