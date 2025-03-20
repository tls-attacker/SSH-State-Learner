/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class SshTransportGraphDetails<S, T> : GraphDetails<S, SshSymbol, T>() {
    var vexDoneState: S? = null
    var kexInitDoneState: S? = null
    var groupNegotiatedState: S? = null
    var keysDerivedState: S? = null
    var kexDoneState: S? = null
    var finState: S? = null

    override fun extractStateNames(): Map<S?, String> {
        val stateNames = super.extractStateNames().toMutableMap()
        stateNames[vexDoneState] = "Protocol Version Exchanged"
        stateNames[kexInitDoneState] = "KEX: Algorithms Negotiated"
        stateNames[groupNegotiatedState] = "KEX: DH Group Negotiated"
        stateNames[keysDerivedState] = "KEX: Keys Derived"
        stateNames[kexDoneState] = "KEX Completed"
        stateNames[finState] = "Protocol Completed"
        return stateNames
    }
}
