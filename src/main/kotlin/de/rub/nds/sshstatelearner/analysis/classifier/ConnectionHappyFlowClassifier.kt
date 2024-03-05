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
import de.rub.nds.sshstatelearner.analysis.data.SshConnectionGraphDetails
import de.rub.nds.sshstatelearner.exceptions.ClassificationException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class ConnectionHappyFlowClassifier<S, T> : Classifier<S, SshSymbol, T, ResponseFingerprint>() {
    override fun performClassification(stateMachine: StateMachine<S, SshSymbol, T, ResponseFingerprint>) {
        stateMachine as SshStateMachine
        val machine = stateMachine.mealyMachine
        val graphDetails = stateMachine.graphDetails as SshConnectionGraphDetails
        val initialState = machine.initialState ?: throw ClassificationException()

        val channelOpenTransition =
            machine.getTransition(initialState, SshSymbol.MSG_CHANNEL_OPEN_SESSION) ?: throw ClassificationException()
        val channelOpenedState = machine.getSuccessor(channelOpenTransition)
        val execRequestTransition = machine.getTransition(channelOpenedState, SshSymbol.MSG_CHANNEL_REQUEST_EXEC) ?: throw ClassificationException()
        val execRequestState = machine.getSuccessor(execRequestTransition)

        graphDetails.happyFlows = mutableListOf(listOf(initialState, channelOpenedState, execRequestState))
        graphDetails.happyFlowTransitions = mutableSetOf(channelOpenTransition, execRequestTransition)
        graphDetails.channelOpenedState = channelOpenedState
        graphDetails.execRequestState = execRequestState
    }
}
