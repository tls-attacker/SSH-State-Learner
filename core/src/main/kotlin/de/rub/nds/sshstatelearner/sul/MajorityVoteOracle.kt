package de.rub.nds.sshstatelearner.sul

import de.learnlib.oracle.MembershipOracle
import de.learnlib.oracle.membership.SULOracle
import de.learnlib.query.Query
import de.learnlib.sul.SUL
import net.automatalib.word.Word

class MajorityVoteOracle<I, O>(
    private val membershipOracle: MembershipOracle<I, Word<O>>,
    private val votes: Int) : MembershipOracle<I, Word<O>> {

    constructor(
        sul: SUL<I, O>,
        votes: Int
    ) : this(SULOracle(sul), votes)

    override fun processQueries(queries: Collection<Query<I, Word<O>>>) {
        for (query in queries) {
            val prefix = query.prefix
            val suffix = query.suffix
            val response = answerQuery(prefix, suffix)
            query.answer(response)
        }
    }

    override fun answerQuery(prefix: Word<I>?, suffix: Word<I>?): Word<O> {
        val responses : MutableList<Word<O>> = mutableListOf()
        for (i in 0 until votes) {
            responses.add(membershipOracle.answerQuery(prefix, suffix))
        }
        return majorityElement(responses)
    }

    /**
     * Returns the majority element of a list of words.
     *
     * @param words The list of words to determine the majority element from.
     * @return The majority element of the list.
     */
    private fun majorityElement(words: List<Word<O>>): Word<O> {
        val distinctWords = HashSet(words)
        var majorityWord = distinctWords.firstOrNull() ?: return Word.epsilon()
        var majorityWordOccurence = words.count { it == majorityWord }
        for (word in distinctWords) {
            var candidateCount = words.count { it == word }
            if (candidateCount > majorityWordOccurence) {
                majorityWord = word
                majorityWordOccurence = candidateCount
            }
        }
        return majorityWord
    }
}