/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.classifier

import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType
import de.rub.nds.sshstatelearner.SshStateMachine
import de.rub.nds.sshstatelearner.StateMachine
import de.rub.nds.sshstatelearner.analysis.data.SshTransportGraphDetails
import de.rub.nds.sshstatelearner.exceptions.ClassificationException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class TransportHappyFlowClassifier<S, T> : Classifier<S, SshSymbol, T, ResponseFingerprint>() {
    override fun performClassification(stateMachine: StateMachine<S, SshSymbol, T, ResponseFingerprint>) {
        stateMachine as SshStateMachine
        val machine = stateMachine.mealyMachine
        val graphDetails = stateMachine.graphDetails as SshTransportGraphDetails
        val initialState = machine.initialState ?: throw ClassificationException()
        val happyFlowTransitions: MutableSet<T> = mutableSetOf()
        val happyFlow = mutableListOf<S>(initialState)

        // Identification of the version exchange transition and state
        val vexState: S = initialState

        // Identification of key exchange init transition and state
        val kexInitTransition = machine.getTransition(vexState, SshSymbol.MSG_KEXINIT) ?: throw ClassificationException()
        val kexInitState = machine.getSuccessor(kexInitTransition)
        happyFlowTransitions.add(kexInitTransition)
        happyFlow.add(kexInitState)

        // Perform classification of key exchange happy flow
        val kexHappyFlow = classifyKexHappyFlow(stateMachine, kexInitState) ?: throw ClassificationException()
        happyFlow.addAll(kexHappyFlow.first)
        happyFlowTransitions.addAll(kexHappyFlow.second)
        val keysDerivedState = happyFlow.last()

        val kexDoneTransition = machine.getTransition(keysDerivedState, SshSymbol.MSG_NEWKEYS) ?: throw ClassificationException()
        val kexDoneState = machine.getSuccessor(kexDoneTransition)
        happyFlowTransitions.add(kexDoneTransition)
        happyFlow.add(kexDoneState)

        val serviceTransition = machine.getTransition(kexDoneState, SshSymbol.MSG_SERVICE_REQUEST_USERAUTH) ?: throw ClassificationException()
        val serviceState = machine.getSuccessor(serviceTransition)
        happyFlowTransitions.add(serviceTransition)
        happyFlow.add(serviceState)

        graphDetails.happyFlows = mutableListOf(happyFlow)
        graphDetails.happyFlowTransitions = happyFlowTransitions
        graphDetails.vexDoneState = vexState
        graphDetails.kexInitDoneState = kexInitState
        if (stateMachine.kexAlgorithm.flowType == KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE) {
            graphDetails.groupNegotiatedState = kexHappyFlow.first.first()
        }
        graphDetails.keysDerivedState = kexHappyFlow.first.last()
        graphDetails.kexDoneState = kexDoneState
        graphDetails.finState = serviceState
    }

    private fun classifyKexHappyFlow(stateMachine: SshStateMachine<S, T>, kexInitState: S): Pair<List<S>, List<T>>? {
        val machine = stateMachine.mealyMachine
        when (stateMachine.kexAlgorithm.flowType) {
            KeyExchangeFlowType.ECDH -> {
                val kexTransition = machine.getTransition(kexInitState, SshSymbol.MSG_KEX_ECDH_INIT) ?: throw ClassificationException()
                val keysDerivedState = machine.getSuccessor(kexTransition)
                return listOf(keysDerivedState) to listOf(kexTransition)
            }
            KeyExchangeFlowType.DIFFIE_HELLMAN -> {
                val kexTransition = machine.getTransition(kexInitState, SshSymbol.MSG_KEXDH_INIT) ?: throw ClassificationException()
                val keysDerivedState = machine.getSuccessor(kexTransition)
                return listOf(keysDerivedState) to listOf(kexTransition)
            }
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> {
                val gexTransition = machine.getTransition(kexInitState, SshSymbol.MSG_KEX_DH_GEX_REQUEST) ?: throw ClassificationException()
                val gexDoneState = machine.getSuccessor(gexTransition)
                val kexTransition = machine.getTransition(gexDoneState, SshSymbol.MSG_KEX_DH_GEX_INIT) ?: throw ClassificationException()
                val keysDerivedState = machine.getSuccessor(kexTransition)
                return listOf(gexDoneState, keysDerivedState) to listOf(gexTransition, kexTransition)
            }
            KeyExchangeFlowType.HYBRID -> {
                val kexTransition = machine.getTransition(kexInitState, SshSymbol.MSG_KEX_HBR_INIT) ?: throw ClassificationException()
                val keysDerivedState = machine.getSuccessor(kexTransition)
                return listOf(keysDerivedState) to listOf(kexTransition)
            }
            KeyExchangeFlowType.RSA -> {
                val kexTransition = machine.getTransition(kexInitState, SshSymbol.MSG_KEX_RSA_SECRET) ?: throw ClassificationException()
                val keysDerivedState = machine.getSuccessor(kexTransition)
                return listOf(keysDerivedState) to listOf(kexTransition)
            }
            else -> return null
        }
    }
}
