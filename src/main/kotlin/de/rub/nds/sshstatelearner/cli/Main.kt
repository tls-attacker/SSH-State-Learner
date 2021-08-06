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
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeRequestMessagePreparator
import de.rub.nds.sshattacker.core.workflow.action.GenericReceiveAction
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.learner.SshSulLearner
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.symbols.GenericMessageSymbol
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import kotlin.system.exitProcess
import net.automatalib.visualization.Visualization
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet
import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.config.Configurator

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
    Configurator.setLevel(LogManager.getLogger(DhGexKeyExchangeRequestMessagePreparator::class.java).name, Level.ERROR)
}

private fun constructAlphabet(): Alphabet<SshSymbol> {
    // TODO: Allow specification of alphabet through CLI
    return ListAlphabet(mutableListOf(
        GenericMessageSymbol(KeyExchangeInitMessage()),
        GenericMessageSymbol(VersionExchangeMessage()),
        GenericMessageSymbol(DisconnectMessage()),
        GenericMessageSymbol(DhGexKeyExchangeRequestMessage()),
        GenericMessageSymbol(IgnoreMessage()),
        GenericMessageSymbol(DebugMessage()),
        GenericMessageSymbol(ServiceRequestMessage())
    ))
}

fun main(vararg args: String) {
    handleArgs(args)
    adjustLogLevels()
    val alphabet = constructAlphabet()
    val sul = SshSul(ArgsSul.hostname, ArgsSul.port, ArgsSul.timeout, ArgsSul.resetDelay)
    val hypothesis = SshSulLearner(alphabet, sul, ArgsLearner.learningAlgorithm).apply {
        equivRandomWordsMinLength = ArgsLearner.equivRandomWordsMinLength
        equivRandomWordsMaxLength = ArgsLearner.equivRandomWordsMaxLength
        equivRandomWordsMaxTests = ArgsLearner.equivRandomWordsMaxTests
    }.learn()
    Visualization.visualize(hypothesis, alphabet)
}
