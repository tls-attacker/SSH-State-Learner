package de.rub.nds.sshstatelearner.analysis.automata

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class AnalysisDFARun(analysisDFACreationHelper: AnalysisDFACreationHelper) {
    val alphabet = analysisDFACreationHelper.alphabet
    private val extendedAlphabet = analysisDFACreationHelper.extendedAlphabet
    private var currentState = analysisDFACreationHelper.getInitialState()
    var falseStateWasReached = false

    private var savedState: AnalysisDFAState? = null
    private var savedFalseStateWasReached: Boolean? = null

    fun step(inputSymbol: SshSymbol?): Boolean {
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

    fun saveState() {
        savedState = currentState
        savedFalseStateWasReached = falseStateWasReached
    }

    fun restoreState() {
        currentState = savedState ?: currentState
        falseStateWasReached = savedFalseStateWasReached ?: falseStateWasReached

    }
}