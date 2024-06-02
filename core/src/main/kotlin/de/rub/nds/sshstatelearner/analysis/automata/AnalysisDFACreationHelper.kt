package de.rub.nds.sshstatelearner.analysis.automata

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.core.JsonParser.Feature
import com.fasterxml.jackson.databind.ObjectMapper
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import java.io.File


class AnalysisDFACreationHelper(
    val alphabet: Set<SshSymbol> = emptySet(),
    val extendedAlphabet: Set<SshSymbol> = emptySet(),
) {
    val states: MutableList<AnalysisDFAState> = mutableListOf<AnalysisDFAState>()

    var currentIdCounter = 0
        private set

    fun readJson(pathToFile: String) {
        fun addAllRecursive(analysisDFAState: AnalysisDFAState, listToAdd: MutableList<AnalysisDFAState>) {
            listToAdd.add(analysisDFAState)
            analysisDFAState.successorTransitions.forEach { it ->
                if (it.successorState != null) addAllRecursive(
                    it.successorState,
                    listToAdd
                )
            }
        }

        val root = ObjectMapper().enable(Feature.INCLUDE_SOURCE_IN_LOCATION)
            .readValue(File(pathToFile), AnalysisDFAState::class.java)
        addAllRecursive(root, states)
    }

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