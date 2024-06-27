package de.rub.nds.sshstatelearner.db

import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import jakarta.persistence.Persistence
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.automatalib.words.Word
import java.time.Instant

class QueryResultManager {

    val localScope = CoroutineScope(Dispatchers.IO)
    val dbChannel: Channel<QueryResult> = Channel(Channel.UNLIMITED)
    val dbQueries: MutableList<QueryResult> = mutableListOf()
    var dbJob: Job? = null
    var currentQueryTyp = QueryTyp.USED_TO_LEARN

    fun init() {
        dbJob = dbJob ?: localScope.launch {
            while (true) {
                val newQueryResult = dbChannel.receive()
                val oldQueryResult = dbQueries.find {
                    it.prefix == newQueryResult.prefix
                            && it.suffix == newQueryResult.suffix
                            && it.responseFingerprints == newQueryResult.responseFingerprints
                            && it.queryTyp == newQueryResult.queryTyp
                }

                if (oldQueryResult != null) {
                    oldQueryResult.count++
                } else {
                    dbQueries.add(newQueryResult)
                }
            }
        }
    }

    fun addDBQueryResult(queryResult: QueryResult) {
        runBlocking {
            dbChannel.send(queryResult)
        }
    }

    fun addDBQueryResult(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, answer: Word<ResponseFingerprint>) {
        addDBQueryResult(
            QueryResult(
                prefix.asList(), suffix.asList(),
                answer.map { QueryResultResponseFingerprint(it.messages.map { it.toCompactString() }, it.socketState) },
                currentQueryTyp
            )
        )
    }

    fun safeToDatabase(jsonConfigString: String) {
        val entityManagerFactory = Persistence.createEntityManagerFactory("default")
        val entityManager = entityManagerFactory.createEntityManager()
        val stlInfo = STLInfo(jsonConfigString, dbQueries, Instant.now())
        entityManager.use {
            it.transaction.begin()
            it.persist(stlInfo)
            it.transaction.commit()
        }
    }

    fun switchToQueryTypes(queryTyp: QueryTyp) {
        currentQueryTyp = queryTyp
    }

}