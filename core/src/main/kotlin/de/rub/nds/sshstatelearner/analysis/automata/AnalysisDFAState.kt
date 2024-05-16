package de.rub.nds.sshstatelearner.analysis.automata

import de.rub.nds.sshstatelearner.extraction.SshSymbol

abstract class AnalysisDFAState(private val id: Int) {
    protected val successorTransitions: MutableSet<AnalysisDFATransition> = mutableSetOf()
    var isAcceptAllState = false
        protected set

    fun getId() = id

    fun addSuccessorTransition(successorTransition: AnalysisDFATransition) {
        if (!isAcceptAllState) {
            successorTransitions.add(successorTransition)
        } else {
            throw IllegalStateException(
                "A state that accepts all inputs cannot have a transition, as all transitions are self-transitions."
            )
        }
    }

    fun getSuccessorState(inputSymbol: SshSymbol): AnalysisDFAState? =
        if (isAcceptAllState) this else successorTransitions.find { it.inputSymbol == inputSymbol }?.successorState
}