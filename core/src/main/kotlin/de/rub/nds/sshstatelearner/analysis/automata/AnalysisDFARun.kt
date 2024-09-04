package de.rub.nds.sshstatelearner.analysis.automata

import de.rub.nds.sshstatelearner.analysis.limiter.SMLRun
import de.rub.nds.sshstatelearner.extraction.SshSymbol

/**
 * Class that simulates the defined DEA for inputs sequentially.
 */
class AnalysisDFARun(analysisDFACreationHelper: AnalysisDFACreationHelper) : SMLRun() {
    val alphabet = analysisDFACreationHelper.alphabet
    private val extendedAlphabet = analysisDFACreationHelper.extendedAlphabet
    private var currentState = analysisDFACreationHelper.getInitialState()
    var falseStateWasReached = false

    private var savedState: AnalysisDFAState? = null
    private var savedFalseStateWasReached: Boolean? = null

    override fun step(inputSymbol: SshSymbol?): Boolean {
        if (inputSymbol == null) throw IllegalArgumentException("Unknown inputSymbol '$inputSymbol'")
        if (falseStateWasReached) return false
        return when (inputSymbol) {
            in alphabet -> {
                val nextState = currentState.getSuccessorState(inputSymbol)
                if (nextState != null) {
                    currentState = nextState
                    true
                } else {
                    falseStateWasReached = true
                    false
                }
            }

            in extendedAlphabet -> {
                return true
            }

            else -> {
                throw IllegalArgumentException("Unknown inputSymbol '$inputSymbol'")
            }
        }
    }

    override fun saveState() {
        savedState = currentState
        savedFalseStateWasReached = falseStateWasReached
    }

    override fun restoreState() {
        currentState = savedState ?: currentState
        falseStateWasReached = savedFalseStateWasReached ?: falseStateWasReached

    }
}