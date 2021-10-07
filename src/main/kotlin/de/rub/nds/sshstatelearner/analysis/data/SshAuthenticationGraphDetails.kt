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

class SshAuthenticationGraphDetails<S, T> : GraphDetails<S, SshSymbol, T>() {
    var authSuccessfulState: S? = null

    override fun extractStateNames(): Map<S?, String> {
        val stateNames = super.extractStateNames().toMutableMap()
        stateNames[initialState] = "SSH Transport Established"
        stateNames[authSuccessfulState] = "Authentication Successful"
        return stateNames
    }
}
