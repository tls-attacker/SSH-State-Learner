package de.rub.nds.sshstatelearner.analysis.classifier

import de.rub.nds.sshstatelearner.StateMachine
import de.rub.nds.sshstatelearner.analysis.data.SshManualGraphDetails
import de.rub.nds.sshstatelearner.exceptions.ClassificationException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

/**
 * Allows a path defined in the configuration file to be represented as a Happy Flow in the graph
 */
class ManuallyClassifier<S, T>(private val stateNameAndSuccessorTransitions: List<StateNameAndSuccessorTransition>) :
    Classifier<S, SshSymbol, T, ResponseFingerprint>() {
    override fun performClassification(stateMachine: StateMachine<S, SshSymbol, T, ResponseFingerprint>) {
        val graphDetails = stateMachine.graphDetails as SshManualGraphDetails
        var currentState = stateMachine.mealyMachine.initialState ?: throw ClassificationException()
        val happyFlow = mutableListOf(currentState)
        for (stateNameSuccessorTransition in stateNameAndSuccessorTransitions) {
            graphDetails.stateToNameMap.put(currentState, stateNameSuccessorTransition.stateName)
            if (stateNameSuccessorTransition.successorTransition != null) {
                val transition = stateMachine.mealyMachine.getTransition(
                    currentState,
                    stateNameSuccessorTransition.successorTransition
                )
                if (transition != null) {
                    graphDetails.happyFlowTransitions.add(transition)
                    currentState =
                        stateMachine.mealyMachine.getSuccessor(transition)
                            ?: throw ClassificationException()
                    happyFlow.add(currentState)
                }
            }
        }
        graphDetails.happyFlows.add(happyFlow)
    }
}