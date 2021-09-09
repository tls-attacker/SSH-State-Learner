/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.cli

import com.beust.jcommander.JCommander
import de.rub.nds.sshattacker.core.util.UnlimitedStrengthEnabler
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.learner.OutputManager
import de.rub.nds.sshstatelearner.learner.SshSulLearner
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.AlphabetFactory
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import java.security.Security
import kotlin.system.exitProcess
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Alphabet
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Prepares the JCE (Java Cryptographic Extension) by adding the BouncyCastle provider and
 * disabling JDK restrictions for strong cryptography (if any).
 */
private fun prepareJCE() {
    Security.addProvider(BouncyCastleProvider())
    UnlimitedStrengthEnabler.enable()
}

/**
 * Parses the CLI arguments using JCommander. If the help flag is set, it displays the usage and exits the application.
 */
private fun handleArgs(args: Array<out String>) {
    val cliArgs = JCommander.newBuilder()
        .addObject(ArgsGeneral)
        .addObject(ArgsSul)
        .addObject(ArgsLearner)
        .args(args)
        .build()

    if (ArgsGeneral.help) {
        cliArgs.usage()
        exitProcess(0)
    }
}

/**
 * Sets the equivalence oracle factory defaults according to the values specified in the
 * ArgsLearner arguments for all supported equivalence oracle types.
 */
private fun setEquivalenceOracleDefaults() {
    EquivalenceOracleFactory.setHappyFlowDefaults(
        ArgsSul.protocolStage,
        ArgsSul.kexAlgorithm,
        ArgsLearner.equivHappyFlowSuffixLength
    )
    EquivalenceOracleFactory.setCompleteExplorationDefaults(
        ArgsLearner.equivCompleteExplorationMinDepth,
        ArgsLearner.equivCompleteExplorationMaxDepth
    )
    EquivalenceOracleFactory.setRandomWordsDefaults(
        ArgsLearner.equivRandomWordsMinLength,
        ArgsLearner.equivRandomWordsMaxLength,
        ArgsLearner.equivRandomWordsMaxTests
    )
    EquivalenceOracleFactory.setRandomWalkDefaults(
        ArgsLearner.equivRandomWalkResetProbability,
        ArgsLearner.equivRandomWalkMaxSteps
    )
    EquivalenceOracleFactory.setWDefaults(
        ArgsLearner.equivWMaxDepth
    )
    EquivalenceOracleFactory.setRandomWDefaults(
        ArgsLearner.equivRandomWMinimalSize,
        ArgsLearner.equivRandomWRndLength,
        ArgsLearner.equivRandomWBound
    )
}

/**
 * Conducts the actual protocol learning.
 *
 * @return A pair of the alphabet used and the hypothesis returned by the SshSulLearner
 */
private fun conductProtocolLearning(): Pair<Alphabet<SshSymbol>, MealyMachine<*, SshSymbol, *, ResponseFingerprint>> {
    val alphabet = AlphabetFactory.construct(ArgsSul.protocolStage, ArgsSul.kexAlgorithm, ArgsSul.receiveDelay)
    val sul = SshSul(ArgsSul.hostname, ArgsSul.port, ArgsSul.timeout, ArgsSul.resetDelay, ArgsSul.protocolStage, ArgsSul.kexAlgorithm)
    val learner = SshSulLearner(alphabet, sul, ArgsLearner.learningAlgorithmType, ArgsLearner.equivOracleChainTypes).apply {
        outputManager = OutputManager<SshSymbol>().apply {
            outputFormats = ArgsLearner.outputFormats.toMutableList()
            outputIntermediateHypothesis = ArgsLearner.outputIntermediateHypothesis
        }
    }
    val hypothesis = learner.learn()
    return Pair(alphabet, hypothesis)
}

fun main(vararg args: String) {
    // TODO: This should be part of the SSH attacker library
    prepareJCE()
    handleArgs(args)
    setEquivalenceOracleDefaults()
    conductProtocolLearning()
}
