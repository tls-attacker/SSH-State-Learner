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
import de.rub.nds.sshstatelearner.constants.EquivalenceOracleType

/**
 * A simple StringConverter converting a comma-separated string of oracle types to a list of (parsed) oracle types.
 */
class EQOracleChainSplitter : IStringConverter<List<EquivalenceOracleType>> {
    /**
     * Converts a comma-separated string to a list of (parsed) oracle types.
     *
     * @param oracleTypes A comma-separated list of valid EquivalenceOracleType names.
     * @return The parsed list of equivalence oracle types.
     */
    override fun convert(oracleTypes: String?): List<EquivalenceOracleType> {
        return oracleTypes?.split(",")
            ?.map { it.trim() }
            ?.map { EquivalenceOracleType.valueOf(it) } ?: emptyList()
    }
}
