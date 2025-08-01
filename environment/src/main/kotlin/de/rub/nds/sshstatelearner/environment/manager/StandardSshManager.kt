package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.config.ConfigHelper
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.AlphabetFactory
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.sul.SshSul
import net.automatalib.alphabet.Alphabet
import net.automatalib.alphabet.impl.ListAlphabet
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
        val learner = Extractor(
            alphabet,
            listOf(sul),
            configGeneral.learnerConfig.learningAlgorithmType,
            configGeneral.learnerConfig.equivOracleChainTypes,
            configGeneral.learnerConfig.outputIntermediateHypothesis,
            configGeneral.outputDirectory,
            configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount,
            2 * configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount + 1
        )
        return learner.extractStateMachine()

    }

    /**
     * It must be possible to fork the SshSul
     */
    abstract fun getSul(): SshSul

    /**
     * Specifies how many SUL instances are forked
     */
    abstract fun getCountOfParallelSuls(): Int

    /**
     * Determines the input alphabet to be used.
     */
    protected fun getInputAlphabet(): Alphabet<SshSymbol> {
        val alphabet =
            when (configGeneral.sulConfig.protocolStage) {
                ProtocolStage.UNKNOWN -> ListAlphabet(configGeneral.sulConfig.alphabet)

                else -> AlphabetFactory.construct(
                    configGeneral.sulConfig.sulType,
                    configGeneral.sulConfig.protocolStage,
                    configGeneral.sulConfig.kexAlgorithm,
                )
            }
        return alphabet
    }

    protected fun serializeExtractorResult(result: Extractor.ExtractorResult) {
        val folder = File(configGeneral.outputDirectory).also { it.mkdirs() }
        // Serialize learned model to DOT and convert to PDF
        result.learnedModel.exportToDotAndPDF(
            File(folder, "finished_${configGeneral.sulConfig.protocolStage}_long.dot"),
            VisualizationDetail.LONG
        )
        result.learnedModel.exportToDotAndPDF(
            File(folder, "finished_${configGeneral.sulConfig.protocolStage}_medium.dot"),
            VisualizationDetail.MEDIUM
        )
        result.learnedModel.exportToDotAndPDF(
            File(folder, "finished_${configGeneral.sulConfig.protocolStage}_short.dot"),
            VisualizationDetail.SHORT
        )
        // Serialize extractor statistics
        val statsFile = File(folder, "statistics.txt").also { it.createNewFile() }
        with(FileWriter(statsFile)) {
            result.statistics.export(this)
            addAdditionalStatistics(this)
            this.close()
        }
        ConfigHelper().safeConfig(configGeneral)
    }

    /**
     * Möglichkeit SUL spezifische Statistikten zu erstellen
     */
    open fun addAdditionalStatistics(fileWriter: FileWriter) {

    }

    /**
     * Ability to generate SUL-specific statistics
     */
    protected fun analyzeExtractorResult(result: Extractor.ExtractorResult) = result.learnedModel.analyzeMealyMachine()

    private fun setEquivalenceOracleDefaults() {
        EquivalenceOracleFactory.setHappyFlowDefaults(
            configGeneral.sulConfig.protocolStage,
            configGeneral.sulConfig.kexAlgorithm,
            configGeneral.learnerConfig.equivHappyFlowMaximumInsertions,
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
            configGeneral.learnerConfig.equivWLookahead,
            configGeneral.learnerConfig.equivWExpectedSize
        )
        EquivalenceOracleFactory.setRandomWDefaults(
            configGeneral.learnerConfig.equivRandomWMinimalSize,
            configGeneral.learnerConfig.equivRandomWRndLength,
            configGeneral.learnerConfig.equivRandomWBound
        )
    }
}