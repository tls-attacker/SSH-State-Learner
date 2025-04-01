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
import de.rub.nds.sshstatelearner.analysis.data.SshAuthenticationGraphDetails
import de.rub.nds.sshstatelearner.exceptions.ClassificationException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class AuthenticationHappyFlowClassifier<S, T> : Classifier<S, SshSymbol, T, ResponseFingerprint>() {
    override fun performClassification(stateMachine: StateMachine<S, SshSymbol, T, ResponseFingerprint>) {
        stateMachine as SshStateMachine
        val machine = stateMachine.mealyMachine
        val graphDetails = stateMachine.graphDetails as SshAuthenticationGraphDetails
        val initialState = machine.initialState ?: throw ClassificationException()

        val authSuccessfulTransition = machine.getTransition(initialState, SshSymbol.MSG_USERAUTH_REQUEST_PASSWORD) ?: throw ClassificationException()
        val authSuccessfulState = machine.getSuccessor(authSuccessfulTransition)

        graphDetails.happyFlows = mutableListOf(listOf(initialState, authSuccessfulState))
        graphDetails.happyFlowTransitions = mutableSetOf(authSuccessfulTransition)
        graphDetails.authSuccessfulState = authSuccessfulState
    }
}
