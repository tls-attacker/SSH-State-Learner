package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class SshConnectionGraphDetails<S, T> : GraphDetails<S, SshSymbol, T>() {
    override fun extractStateNames(): Map<S, String> {
        TODO("Not yet implemented")
    }
}