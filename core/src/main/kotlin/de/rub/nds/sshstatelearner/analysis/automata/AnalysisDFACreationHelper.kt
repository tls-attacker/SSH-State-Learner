package de.rub.nds.sshstatelearner.analysis.automata

import com.fasterxml.jackson.annotation.JsonIgnore
import de.rub.nds.sshstatelearner.extraction.SshSymbol

/**
 * Class used to model the DFA and to save and load it in JSON format for the SML.
 */
class AnalysisDFACreationHelper(
    val alphabet: Set<SshSymbol> = emptySet(),
    val extendedAlphabet: Set<SshSymbol> = emptySet(),
) {
    val states: MutableList<AnalysisDFAState> = mutableListOf<AnalysisDFAState>()

    var currentIdCounter = 0
        private set

    fun createState(): AnalysisDFAState {
        val newState = AnalysisDFAState(currentIdCounter++)
        states.add(newState)
        return newState
    }

    fun createTransitionBetween(
        stateStart: AnalysisDFAState,
        stateEnd: AnalysisDFAState,
        inputSymbol: SshSymbol
    ) {
        stateStart.addSuccessorTransition(AnalysisDFATransition(inputSymbol, stateEnd))
    }

    fun createSelfTransition(state: AnalysisDFAState, inputSymbol: SshSymbol) {
        state.addSuccessorTransition(AnalysisDFATransition(inputSymbol, state))
    }

    fun changeStateToAcceptAllInputSymbols(state: AnalysisDFAState) {
        state.setIsAcceptAllState(true)
    }

    @JsonIgnore
    fun getInitialState(): AnalysisDFAState = states.first()

}