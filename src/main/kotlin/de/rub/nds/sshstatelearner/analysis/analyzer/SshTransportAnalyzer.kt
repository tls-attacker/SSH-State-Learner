/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.analysis.classifier.CommonClassifier
import de.rub.nds.sshstatelearner.analysis.classifier.TransportHappyFlowClassifier
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class SshTransportAnalyzer<S, T> : Analyzer<S, SshSymbol, T, ResponseFingerprint>() {

    init {
        classifiers.add(CommonClassifier())
        classifiers.add(TransportHappyFlowClassifier())
    }
}
