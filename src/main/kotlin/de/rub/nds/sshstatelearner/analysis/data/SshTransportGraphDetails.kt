package de.rub.nds.sshstatelearner.analysis.data

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class SshTransportGraphDetails<S, T> : GraphDetails<S, SshSymbol, T>() {
    var vexDoneState: S? = null
    var kexInitDoneState: S? = null
    var groupNegotiatedState: S? = null
    var kexDoneState: S? = null
    var finState: S? = null

    override fun extractStateNames(): Map<S?, String> {
        val stateNames = super.extractStateNames().toMutableMap()
        stateNames[vexDoneState] = "Protocol Version Exchanged"
        stateNames[kexInitDoneState] = "KEX: Algorithms Negotiated"
        stateNames[groupNegotiatedState] = "KEX: DH Group Negotiated"
        stateNames[kexDoneState] = "KEX: Keys Derived"
        stateNames[finState] = "Protocol Completed"
        return stateNames
    }
}