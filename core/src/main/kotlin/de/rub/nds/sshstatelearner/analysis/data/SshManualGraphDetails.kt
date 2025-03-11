package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class SshManualGraphDetails<S, T> : GraphDetails<S, SshSymbol, T>() {
    val stateToNameMap = mutableMapOf<S, String>()

    override fun extractStateNames(): Map<S?, String> {
        val stateNames = super.extractStateNames().toMutableMap()
        stateNames.putAll(stateToNameMap)
        return stateNames
    }
}