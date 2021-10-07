/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.classifier

import de.rub.nds.sshstatelearner.StateMachine
import de.rub.nds.sshstatelearner.exceptions.ClassificationException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState

class CommonClassifier<S, T> : Classifier<S, SshSymbol, T, ResponseFingerprint>() {
    override fun performClassification(stateMachine: StateMachine<S, SshSymbol, T, ResponseFingerprint>) {
        val machine = stateMachine.mealyMachine
        val alphabet = stateMachine.alphabet
        val initialState = machine.initialState ?: throw ClassificationException()

        // Identify socket states in every state
        val conflicting = mutableSetOf<S>()
        for (state in machine.states) {
            // If state is the initialState assume successful connection (if not we don't get here)
            if (state === initialState) {
                stateMachine.graphDetails.socketStateMap[state] = mutableSetOf(SocketState.UP)
            }
            // Iterate through all outgoing edges from this state
            for (symbol in alphabet) {
                val transition = machine.getTransition(state, symbol)
                val transitionOutput = machine.getTransitionOutput(transition)
                val successor = machine.getSuccessor(transition)
                if (!stateMachine.graphDetails.socketStateMap.contains(successor)) {
                    stateMachine.graphDetails.socketStateMap[successor] = mutableSetOf()
                }
                stateMachine.graphDetails.socketStateMap[successor]?.add(transitionOutput.socketState)
            }
        }

        // Identify error state (the error state contains no outgoing edges, all edges are circular)
        var errorState: S? = null
        for (state in machine.states) {
            var errorStateIndicator = 0
            for (symbol in alphabet) {
                val transition = machine.getTransition(state, symbol) ?: continue
                // If the state contains at least one outgoing edge, the current state is not the error state
                if (state !== machine.getSuccessor(transition)) {
                    errorStateIndicator++
                }
                // If the state contains at least one transition which outputs
                if (machine.getTransitionOutput(transition).socketState != SocketState.CLOSED) {
                    errorStateIndicator++
                }
            }
            if (errorStateIndicator == 0) {
                errorState = state
                break
            }
        }

        stateMachine.graphDetails.initialState = initialState
        stateMachine.graphDetails.errorState = errorState
    }
}
