package de.rub.nds.sshstatelearner.analysis.automata

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class AnalysisDFACreationHelper(val alphabet: Set<SshSymbol>, val extendedAlphabet: Set<SshSymbol>) {
    private val states = mutableListOf<AnalysisDFAState>()
    private var currentIdCounter = 0
    fun createState(): AnalysisDFAState {
        val newState = AnalysisDFAStateImpl(currentIdCounter)
        states.add(newState)
        return newState
    }

    fun createTransitionBetween(
        stateStart: AnalysisDFAState,
        stateEnd: AnalysisDFAState,
        inputSymbol: SshSymbol
    ) {
        stateStart.addSuccessorTransition(AnalysisDFATransitionImpl(inputSymbol, stateEnd))
    }

    fun createSelfTransition(state: AnalysisDFAState, inputSymbol: SshSymbol) {
        state.addSuccessorTransition(AnalysisDFATransitionImpl(inputSymbol, state))
    }

    fun changeStateToAcceptAllInputSymbols(state: AnalysisDFAState) {
        if (state is AnalysisDFAStateImpl) {
            state.setIsAcceptAllState(true)
        } else {
            throw IllegalStateException("Cannot change state to \"accept all input symbols\"")
        }
    }

    fun getInitialState(): AnalysisDFAState = states.first()

    private class AnalysisDFAStateImpl(id: Int) : AnalysisDFAState(id) {
        fun setIsAcceptAllState(value: Boolean) {
            isAcceptAllState = value
            successorTransitions.clear()
        }
    }


    private class AnalysisDFATransitionImpl(inputSymbol: SshSymbol, successorState: AnalysisDFAState) :
        AnalysisDFATransition(inputSymbol, successorState)
}