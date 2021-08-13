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
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleType

class EQOracleChainSplitter : IStringConverter<List<EquivalenceOracleType>> {
    override fun convert(oracleTypes: String?): List<EquivalenceOracleType> {
        return oracleTypes?.split(",")
            ?.map { it.trim() }
            ?.map { EquivalenceOracleType.valueOf(it) } ?: emptyList()
    }
}
