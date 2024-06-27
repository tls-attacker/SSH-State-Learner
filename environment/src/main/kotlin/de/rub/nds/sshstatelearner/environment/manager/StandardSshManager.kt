package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.config.ConfigHelper
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.AlphabetFactory
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.extraction.ParallelOracleExtractor
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import de.rub.nds.sshstatelearner.sul.SshSul
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet
import java.io.File
import java.io.FileWriter

abstract class StandardSshManager(protected val configGeneral: ConfigGeneral) : EnvironmentManager() {

    override fun performLearning() {
        setEquivalenceOracleDefaults()
        val extractorResult = conductProtocolLearning()
        analyzeExtractorResult(extractorResult)
        serializeExtractorResult(extractorResult)
    }

    /**
     * Conducts the actual protocol learning.
     *
     * @return A pair of the alphabet used and the hypothesis returned by the SshSulLearner
     */
    protected open fun conductProtocolLearning(): Extractor.ExtractorResult {
        val alphabet = getInputAlphabet()
        MainWindow.infoAlphabetSize.text = alphabet.size.toString()
        val sul = getSul()

        val learner = ParallelOracleExtractor(
            alphabet,
            sul,
            getCountOfParallelSuls(),
            configGeneral.learnerConfig.learningAlgorithmType,
            configGeneral.learnerConfig.equivOracleChainTypes,
            configGeneral.learnerConfig.outputIntermediateHypothesis,
            configGeneral.outputDirectory,
            configGeneral.sulConfig.sulTyp.isClientAlphabet,
            configGeneral.learnerConfig.smlLimiterTyp,
            configGeneral.learnerConfig.smlLimiterFilePath,
            configGeneral.learnerConfig.batchSize,
            configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount,
            configGeneral.sulConfig.stateNameAndSuccessorTransitions,
            ConfigHelper().toJsonString(configGeneral)
        )
        return learner.extractStateMachine()

    }

    abstract fun getSul(): SshSul
    abstract fun getCountOfParallelSuls(): Int

    protected fun getInputAlphabet(): Alphabet<SshSymbol> {
        val alphabet =
            when (configGeneral.sulConfig.protocolStage) {
                ProtocolStage.CONNECTION, ProtocolStage.TRANSPORT, ProtocolStage.AUTHENTICATION -> AlphabetFactory.construct(
                    configGeneral.sulConfig.protocolStage,
                    configGeneral.sulConfig.kexAlgorithm,
                    configGeneral.sulConfig.sulTyp.isClientAlphabet
                )

                ProtocolStage.UNKNOWN -> ListAlphabet(configGeneral.sulConfig.alphabet)
            }
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
            addAdditionalStatistics(this)
            this.close()
        }
    }

    open fun addAdditionalStatistics(fileWriter: FileWriter) {

    }

    protected fun analyzeExtractorResult(result: Extractor.ExtractorResult) = result.learnedModel.analyzeMealyMachine()

    private fun setEquivalenceOracleDefaults() {
        EquivalenceOracleFactory.setHappyFlowDefaults(
            configGeneral.sulConfig.protocolStage,
            configGeneral.sulConfig.kexAlgorithm,
            configGeneral.learnerConfig.equivHappyFlowSuffixLength,
            configGeneral.learnerConfig.alternativeHappyFlowAlphabet
        )
        EquivalenceOracleFactory.setCompleteExplorationDefaults(
            configGeneral.learnerConfig.equivCompleteExplorationMinDepth,
            configGeneral.learnerConfig.equivCompleteExplorationMaxDepth
        )
        EquivalenceOracleFactory.setRandomWordsDefaults(
            configGeneral.learnerConfig.equivRandomWordsMinLength,
            configGeneral.learnerConfig.equivRandomWordsMaxLength,
            configGeneral.learnerConfig.equivRandomWordsMaxTests
        )
        EquivalenceOracleFactory.setRandomWalkDefaults(
            configGeneral.learnerConfig.equivRandomWalkResetProbability,
            configGeneral.learnerConfig.equivRandomWalkMaxSteps
        )
        EquivalenceOracleFactory.setWDefaults(
            configGeneral.learnerConfig.equivWMaxDepth
        )
        EquivalenceOracleFactory.setRandomWDefaults(
            configGeneral.learnerConfig.equivRandomWMinimalSize,
            configGeneral.learnerConfig.equivRandomWRndLength,
            configGeneral.learnerConfig.equivRandomWBound
        )
    }
}