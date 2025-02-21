package de.rub.nds.sshstatelearner.db

import de.rub.nds.sshstatelearner.algorithms.Statistics
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import jakarta.persistence.Persistence
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.automatalib.words.Word
import org.apache.logging.log4j.LogManager
import java.time.Instant
import kotlin.time.DurationUnit
import kotlin.time.toDuration

/**
 * The DB manager is currently still very complicated. It has only been implemented so far to find errors...
 */
class QueryResultManager {

    private val localScope = CoroutineScope(Dispatchers.IO)
    val dbChannel: Channel<QueryResult> = Channel(Channel.UNLIMITED)
    private val dbQueries: MutableList<QueryResult> = mutableListOf()
    private var dbJob: Job? = null
    private var currentQueryTyp = QueryTyp.USED_TO_LEARN

    companion object {
        private val LOGGER = LogManager.getLogger()
    }


    /**
     * Starts a worker that processes the queue filled by queries from the SML.
     * Transforms the data into a format suitable for the database.
     */
    fun init() {
        dbJob = dbJob ?: localScope.launch {
            while (true) {
                val tryToReceiveNewQueryResult = runCatching { dbChannel.receive() }.onSuccess { newQueryResult ->
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
                if (tryToReceiveNewQueryResult.isFailure) {
                    break
                }
            }
        }
    }

    private fun addDBQueryResult(queryResult: QueryResult) {
        runBlocking {
            dbChannel.send(queryResult)
        }
    }

    fun addDBQueryResult(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, answer: Word<ResponseFingerprint>) {
        addDBQueryResult(
            QueryResult(
                prefix.asList(), suffix.asList(),
                answer.asList()
                    .map {
                        QueryResultResponseFingerprint(
                            it.messages.map { it2 -> it2.toCompactString() },
                            it.socketState
                        )
                    },
                currentQueryTyp
            )
        )
    }

    fun safeToDatabase(jsonConfigString: String) {
        try {
            val entityManagerFactory = Persistence.createEntityManagerFactory("default")
            val entityManager = entityManagerFactory.createEntityManager()
            val stlInfo = STLInfo(jsonConfigString, dbQueries, Instant.now())
            entityManager.use {
                it.transaction.begin()
                it.persist(stlInfo)
                it.transaction.commit()
            }
        } catch (_: RuntimeException) {
            LOGGER.warn("Failed to save to the database!")
        }
    }

    fun setStatistics(statistics: Statistics) {
        statistics.totalQueryCount = dbQueries.sumOf { it.count }.toLong()

        statistics.totalUniqueQueryCount = dbQueries.size.toLong() - dbQueries.filter { currentQuery ->
            dbQueries.any { anyQuery ->
                currentQuery.prefix == anyQuery.prefix
                        && currentQuery.suffix == anyQuery.suffix
                        && currentQuery.responseFingerprints == anyQuery.responseFingerprints
                        && currentQuery.queryTyp != anyQuery.queryTyp
            }
        }.size.toLong() / 2

        statistics.totalMajorityVoteQueryCount = dbQueries.filter { it.count > 1 }.size.toLong()

        statistics.totalNonDeterministicQueryCount = dbQueries.filter { it1 ->
            dbQueries.any { it2 ->
                it1.prefix == it2.prefix
                        && it1.suffix == it2.suffix
                        && it1.responseFingerprints != it2.responseFingerprints
                        && it1.queryTyp == it2.queryTyp
            }
        }.size.toLong()
    }

    fun waitUntilAllIsProcessed() {
        runBlocking {
            // Waits until the queue has been processed
            while (dbChannel.tryReceive().isSuccess) {
                delay(1.toDuration(DurationUnit.SECONDS))
            }
            dbChannel.close()
            dbJob?.let { joinAll(it) }
        }
    }


    fun switchToQueryTypes(queryTyp: QueryTyp) {
        currentQueryTyp = queryTyp
    }

}