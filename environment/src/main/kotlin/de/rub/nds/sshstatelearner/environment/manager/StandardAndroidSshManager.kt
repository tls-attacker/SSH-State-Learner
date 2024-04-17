package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.android.controller.util.AndroidSSHClientControllerFactory
import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.AlphabetFactory
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.SshServerForFingerprint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet
import org.apache.logging.log4j.LogManager
import java.io.File
import java.io.FileWriter

class StandardAndroidSshManager(val argsAndroidGeneral: ArgsAndroidGeneral) : EnvironmentManager() {

    companion object {
        val logger = LogManager.getLogger()
    }


    override fun setUp() {
        logger.info("SetUp")
        try {
            runBlocking() {
                val sshServerForFingerprint = SshServerForFingerprint(argsAndroidGeneral.portToSshServer)
                val fingerprint = launch(Dispatchers.Default) {
                    // 1.SETUP SERVER for fingerprint
                    sshServerForFingerprint.execute()
                    sshServerForFingerprint.close()
                }
                val androidSSHClientController =
                    AndroidSSHClientControllerFactory.getClientController(argsAndroidGeneral)
                val fingerprintAndroid = launch(Dispatchers.Default) {
                    androidSSHClientController.installApp()
                    androidSSHClientController.connectToGetFingerprint()
                    androidSSHClientController.quit()
                }
                try {
                    joinAll(fingerprint, fingerprintAndroid)
                } finally {
                    if (!fingerprint.isCompleted) sshServerForFingerprint.close()
                    if (!fingerprintAndroid.isCompleted) androidSSHClientController.quit()
                }
            }
        } catch (e: Exception) {
            throw IllegalStateException(e.cause)
        }
    }


    fun conductProtocolLearning(): Extractor.ExtractorResult {
        val alphabet = getInputAlphabet(false)
        MainWindow.infoAlphabetSize.text = alphabet.size.toString()
        val sul = NetworkSshClientSul(
            ArgsSul.name,
            argsAndroidGeneral.portToSshServer,
            ArgsSul.timeout,
            ArgsSul.resetDelay,
            ArgsSul.protocolStage,
            ArgsSul.kexAlgorithm

        )
        sul.use {
            val learner = Extractor(
                alphabet,
                it,
                ArgsLearner.learningAlgorithmType,
                ArgsLearner.equivOracleChainTypes,
                ArgsLearner.outputIntermediateHypothesis,
                ArgsGeneral.output,
                false
            )
            return learner.extractStateMachine()
        }
    }

    override fun performLearning() {
        setEquivalenceOracleDefaults()
        runBlocking {
            val stateLearningJob = launch(Dispatchers.Default) {
                val extractorResult = conductProtocolLearning()
                analyzeExtractorResult(extractorResult)
                serializeExtractorResult(extractorResult, "Hostname", "ProtocolStage")
            }

            val androidSSHClientController =
                AndroidSSHClientControllerFactory.getClientController(argsAndroidGeneral)

            val androidSshClientJob = launch(Dispatchers.Default) {
                androidSSHClientController.startStateLearningMode()
                androidSSHClientController.connectForStateLearning()
                androidSSHClientController.quit()
            }

            stateLearningJob.join()
            androidSSHClientController.stopStateLearningMode()
            androidSshClientJob.join()
        }
    }

    protected fun getInputAlphabet(isClientAlphabet: Boolean): Alphabet<SshSymbol> {
        val alphabet = if (ArgsSul.alphabet != null) ListAlphabet(ArgsSul.alphabet) else AlphabetFactory.construct(
            ArgsSul.protocolStage,
            ArgsSul.kexAlgorithm,
            isClientAlphabet
        )
        return alphabet
    }

    override fun setDown() {
        /* Do Nothing */
    }

    protected fun analyzeExtractorResult(result: Extractor.ExtractorResult) = result.learnedModel.analyzeMealyMachine()

    protected fun serializeExtractorResult(result: Extractor.ExtractorResult, hostname: String, protocolStage: String) {
        val folder = File(ArgsGeneral.output).also { it.mkdirs() }
        // Serialize learned model to DOT and convert to PDF
        result.learnedModel.exportToDotAndPDF(
            File(folder, "${hostname}_${protocolStage}_long.dot"),
            VisualizationDetail.LONG
        )
        result.learnedModel.exportToDotAndPDF(
            File(folder, "${hostname}_${protocolStage}_medium.dot"),
            VisualizationDetail.MEDIUM
        )
        result.learnedModel.exportToDotAndPDF(
            File(folder, "${hostname}_${protocolStage}_short.dot"),
            VisualizationDetail.SHORT
        )
        // Serialize extractor statistics
        val statsFile = File(folder, "statistics.txt").also { it.createNewFile() }
        with(FileWriter(statsFile)) {
            result.statistics.export(this)
            this.close()
        }
    }

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
}