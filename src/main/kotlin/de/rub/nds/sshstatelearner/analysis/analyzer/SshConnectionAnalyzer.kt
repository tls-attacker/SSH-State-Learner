package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.analysis.data.SshConnectionGraphDetails
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class SshConnectionAnalyzer<S, T>(graphDetails: SshConnectionGraphDetails<S, T>) : Analyzer<S, SshSymbol, T, ResponseFingerprint>(graphDetails) {

    init {
        TODO("Register SSH connection classifiers")
    }

    override val graphDetails: SshConnectionGraphDetails<S, T>
        get() = super.graphDetails as SshConnectionGraphDetails<S, T>
}