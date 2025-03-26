/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.visualization

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import net.automatalib.serialization.dot.DefaultDOTVisualizationHelper
import net.automatalib.visualization.VisualizationHelper
import net.automatalib.alphabet.Alphabet

class SSHDOTVisualizationHelper<N, E>(
    delegate: VisualizationHelper<N, in E>,
    private val title: String,
    private val alphabet: Alphabet<SshSymbol>,
    private val stage: ProtocolStage,
    private val kexAlgorithm: KeyExchangeAlgorithm,
    private val strictKex: Boolean,
    private val customProtocolStageNameForGraph: String = ""
) : DefaultDOTVisualizationHelper<N, E>(delegate) {

    override fun writePreamble(a: Appendable) {
        val stringSet = HashSet<String>()

        a.append(System.lineSeparator())
        a.append("    labelloc = \"b\"${System.lineSeparator()}")
        a.append("    label = \"Server/Client: $title\n")
        when (stage) {
            ProtocolStage.UNKNOWN -> a.append("    Protocol Stage: $customProtocolStageNameForGraph")
            else -> a.append("    Protocol Stage: $stage")
        }
        if (stage == ProtocolStage.TRANSPORT || stage == ProtocolStage.TRANSPORT_KEX) {
            a.append("\nKEX Algorithm: $kexAlgorithm")
            a.append("\nStrict KEX enabled: $strictKex")
        }
        a.append("\n\n Messages used during testing: \n")
        for (symbol in alphabet) {
            if (!stringSet.contains(symbol.toString())) {
                a.append("${symbol}\n")
                stringSet.add(symbol.toString())
            }
        }
        a.append("\"${System.lineSeparator()}")
        a.append("    fontsize = 30${System.lineSeparator()}")
        a.append("    edge[decorate=\"true\"]${System.lineSeparator()}")
    }

    override fun writePostamble(a: Appendable?) {}
}
