package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.analysis.data.SshAuthenticationGraphDetails
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class SshAuthenticationAnalyzer<S, T>(graphDetails: SshAuthenticationGraphDetails<S, T>) : Analyzer<S, SshSymbol, T, ResponseFingerprint>(graphDetails) {

    init {
        TODO("Register SSH authentication classifiers")
    }

    override val graphDetails: SshAuthenticationGraphDetails<S, T>
        get() = super.graphDetails as SshAuthenticationGraphDetails<S, T>
}