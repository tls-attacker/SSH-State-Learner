/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.tlsattacker.transport.socket.SocketState

abstract class GraphDetails<S, I, T> {
    var initialState: S? = null
    var errorState: S? = null
    var happyFlows: MutableList<List<S>> = mutableListOf()
    var happyFlowTransitions: MutableSet<T> = mutableSetOf()
    var socketStateMap: MutableMap<S, MutableSet<SocketState>> = mutableMapOf()
    var notInStateMachineLearningFocusState: S? = null

    open fun extractStateNames(): Map<S?, String> {
        return mapOf(initialState to "TCP Established", errorState to "TCP Closed")
    }
}
