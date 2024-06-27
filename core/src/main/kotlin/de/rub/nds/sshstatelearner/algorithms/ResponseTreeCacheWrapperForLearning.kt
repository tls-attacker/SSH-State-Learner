package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.api.oracle.EquivalenceOracle
import de.learnlib.api.query.Query
import de.learnlib.filter.cache.LearningCacheOracle
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Word

class ResponseTreeCacheWrapperForLearning(private val responseTreeCache: ResponseTreeCache) :
    LearningCacheOracle.MealyLearningCacheOracle<SshSymbol, ResponseFingerprint> {

    override fun createCacheConsistencyTest(): EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {
        return responseTreeCache.createCacheConsistencyTest()
    }

    override fun processQueries(queries: MutableCollection<out Query<SshSymbol, Word<ResponseFingerprint>>>?) {
        queries?.forEach {
            val pairResponse = responseTreeCache.find(it.prefix, it.suffix)
            var fingerprint = pairResponse.wordResponseFingerprint
            if (fingerprint != null && pairResponse.isMajorityProved) {
                it.answer(fingerprint)
            } else {
                val smlLimiterResponse = responseTreeCache.analysisInputWithSmlLimiter(
                    it.prefix,
                    it.suffix
                )

                fingerprint = smlLimiterResponse ?: responseTreeCache.answerQueryWithMajorityVote(it.prefix, it.suffix)
                it.answer(fingerprint)
                responseTreeCache.overwrite(it.prefix, it.suffix, fingerprint)
            }
        }
    }
}