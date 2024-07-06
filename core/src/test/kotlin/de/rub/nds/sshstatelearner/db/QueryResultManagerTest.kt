package de.rub.nds.sshstatelearner.db

import de.rub.nds.sshstatelearner.algorithms.Statistics
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.automatalib.words.Word
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test


class QueryResultManagerTest {

    val queryResultManager: QueryResultManager = QueryResultManager()

    @Test
    fun setStatistics() {
        queryResultManager.init()
        val statistics = Statistics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        val prefix = Word.fromSymbols(SshSymbol.MSG_IGNORE)
        val suffix = Word.fromSymbols(SshSymbol.MSG_IGNORE)
        val suffix2 = Word.fromSymbols(SshSymbol.MSG_IGNORE, SshSymbol.MSG_NEWKEYS)
        val responseFingerprint =
            Word.fromSymbols(ResponseFingerprint(listOf(SshSymbol.MSG_IGNORE.messageCreator()), SocketState.UP))
        val responseFingerprint2 =
            Word.fromSymbols(ResponseFingerprint(listOf(SshSymbol.MSG_NEWKEYS.messageCreator()), SocketState.UP))

        queryResultManager.addDBQueryResult(prefix, suffix, responseFingerprint)
        queryResultManager.addDBQueryResult(prefix, suffix, responseFingerprint2)
        queryResultManager.addDBQueryResult(prefix, suffix, responseFingerprint2)
        queryResultManager.addDBQueryResult(prefix, suffix, Word.epsilon())
        queryResultManager.addDBQueryResult(prefix, suffix, Word.epsilon())
        queryResultManager.addDBQueryResult(prefix, suffix, Word.epsilon())
        queryResultManager.addDBQueryResult(prefix, suffix2, Word.epsilon())


        //Wait until it is processed
        runBlocking {
            launch {
                while (!queryResultManager.dbChannel.tryReceive().isFailure) {
                    delay(1)
                }
            }
        }

        queryResultManager.setStatistics(statistics)
        assertEquals(7, statistics.totalQueryCount)
        assertEquals(4, statistics.totalUniqueQueryCount)
        assertEquals(2, statistics.totalMajorityVoteQueryCount)
        assertEquals(3, statistics.totalNonDeterministicQueryCount)
    }

}