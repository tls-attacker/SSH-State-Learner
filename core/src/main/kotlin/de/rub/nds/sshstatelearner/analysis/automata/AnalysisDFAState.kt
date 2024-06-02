package de.rub.nds.sshstatelearner.analysis.automata

import com.fasterxml.jackson.annotation.JsonIdentityInfo
import com.fasterxml.jackson.annotation.ObjectIdGenerators
import de.rub.nds.sshstatelearner.extraction.SshSymbol

@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator::class, property = "stateId")
class AnalysisDFAState(stateId: Int = 0) {
    val successorTransitions: MutableSet<AnalysisDFATransition> = mutableSetOf()
    var isAcceptAllState = false
        protected set
    val stateId: Int = stateId

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

    fun setIsAcceptAllState(value: Boolean) {
        isAcceptAllState = value
        successorTransitions.clear()
    }
}