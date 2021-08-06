/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.api.SUL
import de.learnlib.filter.reuse.ReuseCapableOracle
import net.automatalib.words.Word
import net.automatalib.words.WordBuilder

/**
 * A simple wrapper for a SUL to conform to the ReuseCapableOracle interface.
 * As a SUL is considered a black-box without knowledge about its internal states, this wrapper uses the sequence
 * of input symbols executed on the SUL as the current state.
 */
class ReuseCapableSulOracle<I, O>(private val sul: SUL<I, O>) : ReuseCapableOracle<Word<I>, I, O> {

    override fun continueQuery(trace: Word<I>, state: Word<I>): ReuseCapableOracle.QueryResult<Word<I>, O> {
        sul.pre()
        try {
            for (symbol in state) {
                sul.step(symbol)
            }

            val wb = WordBuilder<O>(trace.length())
            for (symbol in trace) {
                wb.add(sul.step(symbol))
            }
            return ReuseCapableOracle.QueryResult(wb.toWord(), state.concat(trace))
        } finally {
            sul.post()
        }
    }

    override fun processQuery(trace: Word<I>): ReuseCapableOracle.QueryResult<Word<I>, O> {
        return continueQuery(trace, Word.epsilon())
    }
}
