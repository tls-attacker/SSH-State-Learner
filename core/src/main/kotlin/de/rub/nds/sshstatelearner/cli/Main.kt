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
import com.googlecode.lanterna.gui2.AsynchronousTextGUIThread
import com.googlecode.lanterna.gui2.MultiWindowTextGUI
import com.googlecode.lanterna.gui2.SeparateTextGUIThread
import com.googlecode.lanterna.screen.TerminalScreen
import com.googlecode.lanterna.terminal.DefaultTerminalFactory
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.constants.ExecutorType
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.AlphabetFactory
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.NetworkSshServerSul
import de.rub.nds.sshstatelearner.sul.SshSul
import net.automatalib.alphabet.impl.ListAlphabet
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.io.File
import java.io.FileWriter
import java.security.Security
import kotlin.system.exitProcess

/**
 * Prepares the JCE (Java Cryptographic Extension) by adding the BouncyCastle providers.
 */
private fun prepareJCE() {
    Security.addProvider(BouncyCastleProvider())
    Security.addProvider(BouncyCastlePQCProvider())
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
        ArgsLearner.equivHappyFlowMaximumInsertions
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
        ArgsLearner.equivWLookahead,
        ArgsLearner.equivWExpectedSize
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
private fun conductProtocolLearning(): Extractor.ExtractorResult {
    val alphabet = if (ArgsSul.alphabet != null) ListAlphabet(ArgsSul.alphabet) else AlphabetFactory.construct(
        ArgsSul.sulType,
        ArgsSul.protocolStage,
        ArgsSul.kexAlgorithm
    )
    MainWindow.infoAlphabetSize.text = alphabet.size.toString()
    val sulList: List<SshSul> = ArgsSul.port.map {
        when (ArgsGeneral.executor) {
            ExecutorType.NETWORK ->
                when (ArgsSul.sulType) {
                    SulType.CLIENT -> NetworkSshClientSul(
                        ArgsSul.name,
                        it,
                        ArgsSul.timeout,
                        ArgsSul.resetDelay,
                        ArgsSul.protocolStage,
                        ArgsSul.kexAlgorithm,
                        ArgsSul.strictKex,
                        ArgsSul.disableRekex,
                        ArgsSul.disableEncryptedNewKeys,
                        ArgsSul.unencryptedStageOnly,
                        ArgsSul.authRequestLimit,
                        ArgsSul.retrieveDelay
                    )

                    SulType.SERVER -> NetworkSshServerSul(
                        ArgsSul.name,
                        ArgsSul.hostname,
                        it,
                        ArgsSul.timeout,
                        ArgsSul.resetDelay,
                        ArgsSul.protocolStage,
                        ArgsSul.kexAlgorithm,
                        ArgsSul.strictKex,
                        ArgsSul.disableRekex,
                        ArgsSul.disableEncryptedNewKeys,
                        ArgsSul.unencryptedStageOnly,
                        ArgsSul.authRequestLimit,
                        ArgsSul.retrieveDelay
                    )
                }
        }
    }
    val learner = Extractor(
        alphabet,
        sulList,
        ArgsLearner.learningAlgorithmType,
        ArgsLearner.equivOracleChainTypes,
        ArgsLearner.outputIntermediateHypothesis,
        ArgsGeneral.output,
        ArgsLearner.majorityVotes,
        ArgsLearner.conflictVotes
    )
    return learner.extractStateMachine()
}

private fun analyzeExtractorResult(result: Extractor.ExtractorResult) = result.learnedModel.analyzeMealyMachine()

private fun serializeExtractorResult(result: Extractor.ExtractorResult) {
    val folder = File(ArgsGeneral.output).also { it.mkdirs() }
    // Serialize learned model to DOT and convert to PDF
    result.learnedModel.exportToDotAndPDF(File(folder, "${ArgsSul.hostname}_${ArgsSul.protocolStage}_long.dot"), VisualizationDetail.LONG)
    result.learnedModel.exportToDotAndPDF(File(folder, "${ArgsSul.hostname}_${ArgsSul.protocolStage}_medium.dot"), VisualizationDetail.MEDIUM)
    result.learnedModel.exportToDotAndPDF(File(folder, "${ArgsSul.hostname}_${ArgsSul.protocolStage}_short.dot"), VisualizationDetail.SHORT)
}

private fun createTextGUI(): MultiWindowTextGUI? {
    return try {
        val term = DefaultTerminalFactory().createTerminalEmulator()
        term.addResizeListener { _, terminalSize -> MainWindow.computeComponentsSize(terminalSize) }
        val screen = TerminalScreen(term).also {
            it.startScreen()
        }
        MultiWindowTextGUI(SeparateTextGUIThread.Factory(), screen).apply {
            addWindow(MainWindow)
            (guiThread as AsynchronousTextGUIThread).start()
        }
    } catch (e: Exception) { null }
}

private fun updateMainWindowInfoPanel() {
    MainWindow.infoServerName.text = ArgsSul.name
    // TODO: CLI parameters
    MainWindow.infoExecutor.text = ArgsGeneral.executor.toString()
    MainWindow.infoTarget.text = when (ArgsGeneral.executor) {
        ExecutorType.NETWORK -> "ssh://${ArgsSul.hostname}:${ArgsSul.port.first()}..${ArgsSul.port.last()}"
    }
    MainWindow.infoStage.text = ArgsSul.protocolStage.toString()
    MainWindow.infoKex.text = ArgsSul.kexAlgorithm.toString()
    MainWindow.infoStrictKex.text = ArgsSul.strictKex.toString()
    // Alphabet size is updated just in time (required if the alphabet has not been specified)
}

private fun destroyTextGUI(gui: MultiWindowTextGUI?) = gui?.run {
    (guiThread as AsynchronousTextGUIThread).stop()
    screen.stopScreen()
}

/**
 * This is the main entrypoint for the SSH-State-Learner module when running in CLI mode.
 */
fun main(vararg args: String) {
    prepareJCE()
    handleArgs(args)

    val gui = createTextGUI()
    updateMainWindowInfoPanel()

    setEquivalenceOracleDefaults()
    val extractorResult = conductProtocolLearning()
    analyzeExtractorResult(extractorResult)
    serializeExtractorResult(extractorResult)

    MainWindow.waitUntilClosed()
    destroyTextGUI(gui)
}
