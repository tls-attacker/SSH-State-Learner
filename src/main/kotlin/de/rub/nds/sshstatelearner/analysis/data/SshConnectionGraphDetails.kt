package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class SshConnectionGraphDetails<S, T> : GraphDetails<S, SshSymbol, T>() {
    var channelOpenedState: S? = null
    var execRequestState: S? = null

    override fun extractStateNames(): Map<S?, String> {
        val stateNames = super.extractStateNames().toMutableMap()
        stateNames[initialState] = "SSH Authenticated Transport"
        stateNames[channelOpenedState] = "Channel Opened"
        stateNames[execRequestState] = "EXEC Request Executed"
        return stateNames
    }
}