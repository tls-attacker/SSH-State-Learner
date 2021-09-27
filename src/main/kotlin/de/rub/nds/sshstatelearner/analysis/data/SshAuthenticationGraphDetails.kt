package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class SshAuthenticationGraphDetails<S, T>: GraphDetails<S, SshSymbol, T>() {
    var authSuccessfulState: S? = null

    override fun extractStateNames(): Map<S?, String> {
        val stateNames = super.extractStateNames().toMutableMap()
        stateNames[initialState] = "SSH Transport Established"
        stateNames[authSuccessfulState] = "Authentication Successful"
        return stateNames
    }
}