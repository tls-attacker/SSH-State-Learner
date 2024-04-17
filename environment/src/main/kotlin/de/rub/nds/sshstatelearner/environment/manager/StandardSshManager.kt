package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.constants.ExecutorType
import de.rub.nds.sshstatelearner.constants.SULTyp
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.AlphabetFactory
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.NetworkSshServerSul
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet
import java.io.File
import java.io.FileWriter

open class StandardSshManager() : EnvironmentManager() {
    override fun setUp() {
        /* Do Nothing */
    }

    override fun performLearning() {
        val extractorResult = conductProtocolLearning()
        analyzeExtractorResult(extractorResult)
        serializeExtractorResult(extractorResult)
    }

    override fun setDown() {
        /* Do Nothing */
    }

    /**
     * Conducts the actual protocol learning.
     *
     * @return A pair of the alphabet used and the hypothesis returned by the SshSulLearner
     */
    protected open fun conductProtocolLearning(): Extractor.ExtractorResult {
        val alphabet = getInputAlphabet()
        MainWindow.infoAlphabetSize.text = alphabet.size.toString()
        when (ArgsGeneral.executor) {
//        ExecutorType.NYX -> NyxSshSul(
//            ArgsSul.name,
//            "/home/fabian/Workspace/targets/packed_targets/nyx_openssh",
//            "/tmp/nyx",
//            0,
//            ArgsSul.timeout,
//            ArgsSul.resetDelay,
//            ArgsSul.protocolStage,
//            ArgsSul.kexAlgorithm
//        )

            ExecutorType.NYX, ExecutorType.NETWORK ->
                when (ArgsSul.sulTyp) {
                    SULTyp.CLIENT_IS_UNDER_TEST -> NetworkSshClientSul(
                        ArgsSul.name,
                        ArgsSul.port,
                        ArgsSul.timeout,
                        ArgsSul.resetDelay,
                        ArgsSul.protocolStage,
                        ArgsSul.kexAlgorithm
                    )

                    SULTyp.SERVER_IS_UNDER_TEST -> NetworkSshServerSul(
                        ArgsSul.name,
                        ArgsSul.hostname,
                        ArgsSul.port,
                        ArgsSul.timeout,
                        ArgsSul.resetDelay,
                        ArgsSul.protocolStage,
                        ArgsSul.kexAlgorithm
                    )
                }

        }.use {
            val learner = Extractor(
                alphabet,
                it,
                ArgsLearner.learningAlgorithmType,
                ArgsLearner.equivOracleChainTypes,
                ArgsLearner.outputIntermediateHypothesis,
                ArgsGeneral.output,
                ArgsSul.sulTyp.isClientAlphabet
            )
            return learner.extractStateMachine()
        }
    }

    protected fun getInputAlphabet(): Alphabet<SshSymbol> {
        val alphabet = if (ArgsSul.alphabet != null) ListAlphabet(ArgsSul.alphabet) else AlphabetFactory.construct(
            ArgsSul.protocolStage,
            ArgsSul.kexAlgorithm,
            ArgsSul.sulTyp.isClientAlphabet
        )
        return alphabet
    }

    protected fun serializeExtractorResult(result: Extractor.ExtractorResult) {
        val folder = File(ArgsGeneral.output).also { it.mkdirs() }
        // Serialize learned model to DOT and convert to PDF
        result.learnedModel.exportToDotAndPDF(
            File(folder, "${ArgsSul.hostname}_${ArgsSul.protocolStage}_long.dot"),
            VisualizationDetail.LONG
        )
        result.learnedModel.exportToDotAndPDF(
            File(folder, "${ArgsSul.hostname}_${ArgsSul.protocolStage}_medium.dot"),
            VisualizationDetail.MEDIUM
        )
        result.learnedModel.exportToDotAndPDF(
            File(folder, "${ArgsSul.hostname}_${ArgsSul.protocolStage}_short.dot"),
            VisualizationDetail.SHORT
        )
        // Serialize extractor statistics
        val statsFile = File(folder, "statistics.txt").also { it.createNewFile() }
        with(FileWriter(statsFile)) {
            result.statistics.export(this)
            this.close()
        }
    }

    protected fun analyzeExtractorResult(result: Extractor.ExtractorResult) = result.learnedModel.analyzeMealyMachine()
}