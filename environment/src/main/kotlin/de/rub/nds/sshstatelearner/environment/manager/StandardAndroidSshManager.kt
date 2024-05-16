package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.AlphabetFactory
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.extraction.ParallelOracleExtractor
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.AndroidSshClientWorker
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSulProxy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet
import org.apache.logging.log4j.LogManager
import java.io.File
import java.io.FileWriter

class StandardAndroidSshManager(val argsAndroidGeneral: ArgsAndroidGeneral) : EnvironmentManager() {

    private val androidClientConnectionHandler: MutableList<AndroidClientConnectionHandler> = mutableListOf()

    private companion object {
        val logger = LogManager.getLogger()
    }


    override fun setUp() {
        logger.info("SetUp")
        runBlocking {

            var tmp = AndroidClientConnectionHandler("emulator-5554", 48223)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5556", 48224)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5558", 48225)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5560", 48226)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5562", 48227)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5564", 48228)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5566", 48229)
            androidClientConnectionHandler.add(tmp)
            tmp = AndroidClientConnectionHandler("emulator-5568", 48230)
            androidClientConnectionHandler.add(tmp)
            androidClientConnectionHandler.forEach(
                {
                    launch(Dispatchers.IO) {
                        it.init()
                    }
                }
            )
        }
    }


    fun conductProtocolLearning(): Extractor.ExtractorResult {
        //val alphabet = getInputAlphabet(false)
        val alphabet = ListAlphabet(
            listOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_FAILURE,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )
        )
        MainWindow.infoAlphabetSize.text = alphabet.size.toString()
        val suls = mutableListOf<NetworkSshClientSul>()
        for (clientConnectionHandler in androidClientConnectionHandler) {
            suls.add(
                NetworkSshClientSul(
                    ArgsSul.name,
                    clientConnectionHandler.getPort(),
                    ArgsSul.timeout,
                    ArgsSul.resetDelay,
                    ArgsSul.protocolStage,
                    ArgsSul.kexAlgorithm,
                    clientConnectionHandler
                )
            )
        }
        val androidSshClientWorker = AndroidSshClientWorker()
        androidSshClientWorker.init(suls)


        val sul = NetworkSshClientSulProxy(
            ArgsSul.name,
            ArgsSul.timeout,
            ArgsSul.resetDelay,
            ArgsSul.protocolStage,
            ArgsSul.kexAlgorithm,
            androidSshClientWorker
        )
        sul.use {
            val learner = ParallelOracleExtractor(
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
        val extractorResult = conductProtocolLearning()
        analyzeExtractorResult(extractorResult)
        serializeExtractorResult(extractorResult, "Hostname", "ProtocolStage")
        androidClientConnectionHandler.forEach { it.destroy() }
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