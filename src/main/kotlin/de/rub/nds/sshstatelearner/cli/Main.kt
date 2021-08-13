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
import de.rub.nds.sshattacker.core.protocol.common.Handler
import de.rub.nds.sshattacker.core.protocol.common.Preparator
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.util.UnlimitedStrengthEnabler
import de.rub.nds.sshattacker.core.workflow.action.GenericReceiveAction
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.learner.SshSulLearner
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.sshstatelearner.sul.symbols.toSymbol
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import java.security.Security
import kotlin.system.exitProcess
import net.automatalib.visualization.Visualization
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet
import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.config.Configurator
import org.bouncycastle.jce.provider.BouncyCastleProvider

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

private fun adjustLogLevels() {
    Configurator.setRootLevel(Level.INFO)
    Configurator.setLevel(LogManager.getLogger(GenericReceiveAction::class.java).name, Level.WARN)
    Configurator.setLevel(LogManager.getLogger(ClientTcpTransportHandler::class.java).name, Level.WARN)
    // DhGexKeyExchangeRequestMessagePreparator will warn if kex algorithm not set
    Configurator.setLevel(LogManager.getLogger(Preparator::class.java).name, Level.ERROR)
    Configurator.setLevel(LogManager.getLogger(Handler::class.java).name, Level.ERROR)
}

private fun constructAlphabet(): Alphabet<SshSymbol> {
    // TODO: Allow specification of alphabet through CLI
    return ListAlphabet(mutableListOf(
        VersionExchangeMessage().toSymbol(ArgsSul.receiveDelay),
        KeyExchangeInitMessage().toSymbol(ArgsSul.receiveDelay),
        DhGexKeyExchangeRequestMessage().toSymbol(ArgsSul.receiveDelay),
        DhGexKeyExchangeInitMessage().toSymbol(ArgsSul.receiveDelay),
        NewKeysMessage().toSymbol(ArgsSul.receiveDelay),
        ServiceRequestMessage().toSymbol(ArgsSul.receiveDelay)
    ))
}

private fun setEquivalenceOracleDefaults() {
    EquivalenceOracleFactory.setHappyFlowDefaults(
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

fun main(vararg args: String) {
    Security.addProvider(BouncyCastleProvider())
    UnlimitedStrengthEnabler.enable()

    handleArgs(args)
    adjustLogLevels()
    val alphabet = constructAlphabet()
    val sul = SshSul(ArgsSul.hostname, ArgsSul.port, ArgsSul.timeout, ArgsSul.resetDelay)
    setEquivalenceOracleDefaults()
    val hypothesis = SshSulLearner(alphabet, sul, ArgsLearner.learningAlgorithmType, ArgsLearner.equivOracleChainTypes).learn()
    Visualization.visualize(hypothesis, alphabet)
}
