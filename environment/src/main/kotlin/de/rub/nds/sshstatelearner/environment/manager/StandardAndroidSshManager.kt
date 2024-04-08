package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsLearner
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.extraction.Extractor
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSulManager

class StandardAndroidSshManager() : StandardSshManager() {

    val numberOfClientSul = 1
    override fun setUp() {
        //val configs = createAllAndroidAppiumControllerInput()
//        for (config in configs) {
//            // 1.SETUP SERVER for fingerprint
//            val sshServerForFingerprint = SshServerForFingerprint(config.portToServer)
//
//            // 2.Client get fingerprint
//            val androidSSHClientController = JuiceSSHController(
//                config.ipToAppium,
//                config.portToAppium,
//                config.ipToServer,
//                config.portToServer,
//
//                config.udid
//            )
//            androidSSHClientController.installApp()
//            androidSSHClientController.connectToGetFingerprint()
//
//            sshServerForFingerprint.close()
//            // 3.Client start connect
//
//        }
        // 4.Start Learning
        //
    }


    override fun conductProtocolLearning(): Extractor.ExtractorResult {
        val alphabet = getInputAlphabet()
        MainWindow.infoAlphabetSize.text = alphabet.size.toString()
        val sul = NetworkSshClientSulManager(
            numberOfClientSul,
            ArgsSul.port,
            ArgsSul.name,
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
                ArgsGeneral.output
            )
            return learner.extractStateMachine()
        }
    }

    override fun performLearning() {
        val extractorResult = conductProtocolLearning()
        analyzeExtractorResult(extractorResult)
        serializeExtractorResult(extractorResult)
    }

    override fun setDown() {
        /* Do Nothing */
    }
}