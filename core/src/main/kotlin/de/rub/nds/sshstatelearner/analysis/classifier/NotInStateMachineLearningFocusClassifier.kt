/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.classifier

import de.rub.nds.sshstatelearner.SshStateMachine
import de.rub.nds.sshstatelearner.StateMachine
import de.rub.nds.sshstatelearner.analysis.limiter.message.NotInStateMachineLearningFocusMessage
import de.rub.nds.sshstatelearner.exceptions.ClassificationException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class NotInStateMachineLearningFocusClassifier<S, T> : Classifier<S, SshSymbol, T, ResponseFingerprint>() {
    override fun performClassification(stateMachine: StateMachine<S, SshSymbol, T, ResponseFingerprint>) {
        stateMachine as SshStateMachine
        val machine = stateMachine.mealyMachine
        val graphDetails = stateMachine.graphDetails
        val initialState = machine.initialState ?: throw ClassificationException()

        val reachableStatesWithoutNotInStateMachineLearningFocusTransitionOutput = mutableSetOf<S>(initialState)
        for (state in machine.states) {
            for (symbol in stateMachine.alphabet) {
                val transition = machine.getTransition(state, symbol)
                if (transition != null) {
                    val output = machine.getTransitionOutput(transition)
                    val nextState = machine.getSuccessor(transition)
                    if (state != nextState && output.messages.none { it is NotInStateMachineLearningFocusMessage }) {
                        reachableStatesWithoutNotInStateMachineLearningFocusTransitionOutput.add(
                            machine.getSuccessor(
                                transition
                            )
                        )
                    }
                }
            }
        }

        val allState =
            machine.states.filter { it !in reachableStatesWithoutNotInStateMachineLearningFocusTransitionOutput }
                .toList()
        if (allState.size == 1) {
            graphDetails.notInStateMachineLearningFocusState = allState.first()
        }
    }
}
