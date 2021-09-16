/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.cli.args

import com.beust.jcommander.IStringConverter
import de.rub.nds.sshstatelearner.extraction.SshSymbol

/**
 * A simple StringConverter converting a comma-separated string of ssh symbol names to a list of (parsed) ssh symbols.
 */
class SshSymbolSplitter : IStringConverter<List<SshSymbol>> {
    /**
     * Converts a comma-separated string to a list of (parsed) ssh symbols.
     *
     * @param sshSymbols A comma-separated list of valid SshSymbol names.
     * @return The parsed list of ssh symbols.
     */
    override fun convert(sshSymbols: String?): List<SshSymbol> {
        return sshSymbols?.split(",")
            ?.map { it.trim() }
            ?.map { SshSymbol.valueOf(it) }
            ?: emptyList()
    }
}
