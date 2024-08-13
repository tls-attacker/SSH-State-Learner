package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import com.github.victools.jsonschema.generator.FieldScope
import com.github.victools.jsonschema.generator.OptionPreset
import com.github.victools.jsonschema.generator.SchemaGenerator
import com.github.victools.jsonschema.generator.SchemaGeneratorConfigBuilder
import com.github.victools.jsonschema.generator.SchemaVersion
import com.github.victools.jsonschema.module.jackson.JacksonModule
import com.github.victools.jsonschema.module.jackson.JacksonOption
import de.rub.nds.sshstatelearner.analysis.classifier.StateNameAndSuccessorTransition
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp
import de.rub.nds.sshstatelearner.constants.EquivalenceOracleType
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import java.io.File

fun createConfigSchemaJson(outputDir: String) {
    fun addDefaultValueAnnotationProcessing(schemaGeneratorConfigBuilder: SchemaGeneratorConfigBuilder) {
        schemaGeneratorConfigBuilder.forFields().withDefaultResolver { field: FieldScope ->
            val annotation = field.getAnnotationConsideringFieldAndGetter(
                JsonProperty::class.java
            )
            if (annotation == null || annotation.defaultValue.isEmpty()) null else annotation.defaultValue
        }
    }

    val jacksonModule = JacksonModule(JacksonOption.RESPECT_JSONPROPERTY_REQUIRED)
    val schemaGeneratorConfigBuilder =
        SchemaGeneratorConfigBuilder(SchemaVersion.DRAFT_2020_12, OptionPreset.PLAIN_JSON)
            .with(jacksonModule)
    addDefaultValueAnnotationProcessing(schemaGeneratorConfigBuilder)
    val schemaGeneratorConfig = schemaGeneratorConfigBuilder.build()
    val schemaGenerator = SchemaGenerator(schemaGeneratorConfig)
    val configSchemaJson = schemaGenerator.generateSchema(ConfigGeneral::class.java)
    File(outputDir + "/configGeneral.schema.json").writeText(configSchemaJson.toPrettyString())
}

fun createDefaultConfigs(outputDir: String) {
    val objectMapper = ObjectMapper()
    val prettyObjectWriter = objectMapper.writerWithDefaultPrettyPrinter()
    val configGeneral = ConfigGeneral()
    configGeneral.sulConfig = ConfigClientSul()
    prettyObjectWriter.writeValue(File(outputDir + "configClientSul.json"), configGeneral)

    configGeneral.sulConfig = ConfigServerSul()
    prettyObjectWriter.writeValue(File(outputDir + "configServerSul.json"), configGeneral)

    configGeneral.sulConfig = ConfigAndroidClientSul()
    prettyObjectWriter.writeValue(File(outputDir + "configAndroidClientSul.json"), configGeneral)
}

fun createConfigForAnalysis(outputDir: String) {
    fun safeFile(filePathToSafe: String, configGeneral: ConfigGeneral) {
        val objectMapper = ObjectMapper()
        val prettyObjectWriter = objectMapper.writerWithDefaultPrettyPrinter()
        prettyObjectWriter.writeValue(File("$filePathToSafe.json"), configGeneral)
    }

    fun setClientTypSpecific(configGeneral: ConfigGeneral, androidClientTyp: AndroidSshClientTyp) {
        val androidSulConfig = configGeneral.sulConfig as ConfigAndroidClientSul
        when (androidClientTyp) {
            AndroidSshClientTyp.TERMIUS -> {
                androidSulConfig.name = "Termius v6.1.2"
                androidSulConfig.androidSshClientTyp = AndroidSshClientTyp.TERMIUS
                androidSulConfig.pathToApks = listOf(
                    "/home/jimba/apks/termius/base.apk",
                    "/home/jimba/apks/termius/split_config.x86_64.apk",
                    "/home/jimba/apks/termius/split_config.xhdpi.apk"
                )

            }

            AndroidSshClientTyp.JUICE_SSH -> {
                androidSulConfig.name = "Juicessh v3.2.2_200"
                androidSulConfig.androidSshClientTyp = AndroidSshClientTyp.JUICE_SSH
                androidSulConfig.pathToApks = listOf("/home/jimba/apks/juicessh-v3.2.2_200.apk")
            }

            AndroidSshClientTyp.CONNECT_BOT -> {
                androidSulConfig.name = "ConnectBot v1.9.10-19"
                androidSulConfig.androidSshClientTyp = AndroidSshClientTyp.CONNECT_BOT
                androidSulConfig.pathToApks = listOf("/home/jimba/apks/ConnectBot-git-v1.9.10-19.apk")
            }

            else -> {
                throw IllegalStateException("Unknown config type: ${androidClientTyp.name}")
            }
        }
    }

    fun createDefaultConfig(): ConfigGeneral {
        val configGeneral = ConfigGeneral()
        configGeneral.outputDirectory = "/home/jimba/Schreibtisch/config/"

        val learnerConfig = configGeneral.learnerConfig
        learnerConfig.equivOracleChainTypes = listOf(
            EquivalenceOracleType.CACHE_CONSISTENCY,
            EquivalenceOracleType.HAPPY_FLOW,
            EquivalenceOracleType.COMPLETE_EXPLORATION
        )
        learnerConfig.outputIntermediateHypothesis = true

        val configAndroidClientSul = ConfigAndroidClientSul().apply { configGeneral.sulConfig = this }
        configAndroidClientSul.timeout = 50

        val emulatorIds = listOf(
            "emulator-5554",
            "emulator-5556",
            "emulator-5558",
            "emulator-5560",
            "emulator-5562",
            "emulator-5564",
            "emulator-5566",
            "emulator-5568",
            "emulator-5570",
            "emulator-5572",
            "emulator-5574",
            "emulator-5576",
            "emulator-5578",
            "emulator-5580",
            "emulator-5582",
            "emulator-5584"
        )
        configAndroidClientSul.androidConnectionInfos = emulatorIds.mapIndexed { index, emulatorId ->
            ConfigAndroidClientSul.AndroidConnectionInfo(
                "10.0.2.2", 30031 + index,
                "127.0.0.1", 4723, emulatorId
            )
        }
        return configGeneral
    }

    fun createTransportLayerConfig_Eigenschaft1347(
        filePathToSave: String
    ) {
        val configName = "TransportLayer_Eigenschaft1347"
        for (androidSshClientTyp in listOf(
            AndroidSshClientTyp.TERMIUS,
            AndroidSshClientTyp.JUICE_SSH,
            AndroidSshClientTyp.CONNECT_BOT
        )) {
            val configGeneral = createDefaultConfig()
            configGeneral.outputDirectory += androidSshClientTyp.name + "_" + configName
            configGeneral.sulConfig.protocolStage = ProtocolStage.UNKNOWN
            configGeneral.sulConfig.customProtocolStageNameForGraph = "Transport-Layer"

            configGeneral.learnerConfig.equivCompleteExplorationMinDepth = 5
            configGeneral.learnerConfig.equivCompleteExplorationMaxDepth = 5
            configGeneral.learnerConfig.equivHappyFlowSuffixLength = 3

            configGeneral.learnerConfig.alternativeHappyFlowAlphabet = listOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.alphabet = listOf(
                //ServerMessages
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.stateNameAndSuccessorTransitions = listOf(
                StateNameAndSuccessorTransition("Protocol Version Exchanged", SshSymbol.MSG_KEXINIT),
                StateNameAndSuccessorTransition("KEX: Algorithms Negotiated", SshSymbol.MSG_KEX_ECDH_REPLY),
                StateNameAndSuccessorTransition("KEX: DH Group Negotiated", SshSymbol.MSG_NEWKEYS),
                StateNameAndSuccessorTransition("KEX: Keys Derived", SshSymbol.MSG_SERVICE_ACCEPT),
                StateNameAndSuccessorTransition("Transport Layer completed", SshSymbol.MSG_USERAUTH_SUCCESS),
                StateNameAndSuccessorTransition("Authentication Layer completed "),
            )
            when (androidSshClientTyp) {
                AndroidSshClientTyp.TERMIUS -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.JUICE_SSH -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.CONNECT_BOT -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 64
                }

                else -> {}
            }
            safeFile(filePathToSave + "${androidSshClientTyp.name}_$configName", configGeneral)
        }
    }

    fun createTransportLayerConfig_Eigenschaft5(
        filePathToSave: String
    ) {
        val configName = "TransportLayer_Eigenschaft5"
        for (androidSshClientTyp in listOf(
            AndroidSshClientTyp.TERMIUS,
            AndroidSshClientTyp.JUICE_SSH,
            AndroidSshClientTyp.CONNECT_BOT
        )) {
            val configGeneral = createDefaultConfig()
            configGeneral.outputDirectory += androidSshClientTyp.name + "_" + configName
            configGeneral.sulConfig.protocolStage = ProtocolStage.UNKNOWN
            configGeneral.sulConfig.customProtocolStageNameForGraph = "Transport-Layer"

            configGeneral.learnerConfig.equivCompleteExplorationMinDepth = 5
            configGeneral.learnerConfig.equivCompleteExplorationMaxDepth = 5
            configGeneral.learnerConfig.equivHappyFlowSuffixLength = 3

            configGeneral.learnerConfig.alternativeHappyFlowAlphabet = listOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.alphabet = listOf(
                //ServerMessages
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS,
                SshSymbol.MSG_USERAUTH_FAILURE
            )

            configGeneral.sulConfig.stateNameAndSuccessorTransitions = listOf(
                StateNameAndSuccessorTransition("Protocol Version Exchanged", SshSymbol.MSG_KEXINIT),
                StateNameAndSuccessorTransition("KEX: Algorithms Negotiated", SshSymbol.MSG_KEX_ECDH_REPLY),
                StateNameAndSuccessorTransition("KEX: DH Group Negotiated", SshSymbol.MSG_NEWKEYS),
                StateNameAndSuccessorTransition("KEX: Keys Derived", SshSymbol.MSG_SERVICE_ACCEPT),
                StateNameAndSuccessorTransition("Transport Layer completed", SshSymbol.MSG_USERAUTH_SUCCESS),
                StateNameAndSuccessorTransition("Authentication Layer completed "),
            )
            when (androidSshClientTyp) {
                AndroidSshClientTyp.TERMIUS -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.JUICE_SSH -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.CONNECT_BOT -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 64
                }

                else -> {}
            }
            safeFile(filePathToSave + "${androidSshClientTyp.name}_$configName", configGeneral)
        }
    }

    fun createTransportLayerConfig_Eigenschaft2(
        filePathToSave: String
    ) {
        val configName = "TransportLayer_Eigenschaft2"
        for (androidSshClientTyp in listOf(
            AndroidSshClientTyp.TERMIUS,
            AndroidSshClientTyp.JUICE_SSH,
            AndroidSshClientTyp.CONNECT_BOT
        )) {
            val configGeneral = createDefaultConfig()
            configGeneral.outputDirectory += androidSshClientTyp.name + "_" + configName
            configGeneral.sulConfig.protocolStage = ProtocolStage.UNKNOWN
            configGeneral.sulConfig.customProtocolStageNameForGraph = "Transport-Layer"

            configGeneral.learnerConfig.equivCompleteExplorationMinDepth = 5
            configGeneral.learnerConfig.equivCompleteExplorationMaxDepth = 5
            configGeneral.learnerConfig.equivHappyFlowSuffixLength = 3

            configGeneral.learnerConfig.alternativeHappyFlowAlphabet = listOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.alphabet = listOf(
                //ServerMessages
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS,
                SshSymbol.MSG_USERAUTH_FAILURE,
                //ClientMessages
                SshSymbol.MSG_KEX_ECDH_INIT,
                SshSymbol.MSG_SERVICE_REQUEST_USERAUTH,
            )

            configGeneral.sulConfig.stateNameAndSuccessorTransitions = listOf(
                StateNameAndSuccessorTransition("Protocol Version Exchanged", SshSymbol.MSG_KEXINIT),
                StateNameAndSuccessorTransition("KEX: Algorithms Negotiated", SshSymbol.MSG_KEX_ECDH_REPLY),
                StateNameAndSuccessorTransition("KEX: DH Group Negotiated", SshSymbol.MSG_NEWKEYS),
                StateNameAndSuccessorTransition("KEX: Keys Derived", SshSymbol.MSG_SERVICE_ACCEPT),
                StateNameAndSuccessorTransition("Transport Layer completed", SshSymbol.MSG_USERAUTH_SUCCESS),
                StateNameAndSuccessorTransition("Authentication Layer completed "),
            )
            when (androidSshClientTyp) {
                AndroidSshClientTyp.TERMIUS -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.JUICE_SSH -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.CONNECT_BOT -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 64
                }

                else -> {}
            }
            safeFile(filePathToSave + "${androidSshClientTyp.name}_$configName", configGeneral)
        }
    }

    fun createTransportLayerConfig_Eigenschaft6(
        filePathToSave: String
    ) {
        val configName = "TransportLayer_Eigenschaft6"
        for (androidSshClientTyp in listOf(
            AndroidSshClientTyp.TERMIUS,
            AndroidSshClientTyp.JUICE_SSH,
            AndroidSshClientTyp.CONNECT_BOT
        )) {
            val configGeneral = createDefaultConfig()
            configGeneral.outputDirectory += androidSshClientTyp.name + "_" + configName
            configGeneral.sulConfig.protocolStage = ProtocolStage.UNKNOWN
            configGeneral.sulConfig.customProtocolStageNameForGraph = "Transport-Layer"

            configGeneral.learnerConfig.equivCompleteExplorationMinDepth = 5
            configGeneral.learnerConfig.equivCompleteExplorationMaxDepth = 5
            configGeneral.learnerConfig.equivHappyFlowSuffixLength = 3

            configGeneral.learnerConfig.alternativeHappyFlowAlphabet = listOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.alphabet = listOf(
                //ServerMessages
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS,
                SshSymbol.MSG_DISCONNECT
            )

            configGeneral.sulConfig.stateNameAndSuccessorTransitions = listOf(
                StateNameAndSuccessorTransition("Protocol Version Exchanged", SshSymbol.MSG_KEXINIT),
                StateNameAndSuccessorTransition("KEX: Algorithms Negotiated", SshSymbol.MSG_KEX_ECDH_REPLY),
                StateNameAndSuccessorTransition("KEX: DH Group Negotiated", SshSymbol.MSG_NEWKEYS),
                StateNameAndSuccessorTransition("KEX: Keys Derived", SshSymbol.MSG_SERVICE_ACCEPT),
                StateNameAndSuccessorTransition("Transport Layer completed", SshSymbol.MSG_USERAUTH_SUCCESS),
                StateNameAndSuccessorTransition("Authentication Layer completed "),
            )
            when (androidSshClientTyp) {
                AndroidSshClientTyp.TERMIUS -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.JUICE_SSH -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.CONNECT_BOT -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 64
                }

                else -> {}
            }
            safeFile(filePathToSave + "${androidSshClientTyp.name}_$configName", configGeneral)
        }
    }

    fun createTransportLayerConfig_Eigenschaft8(
        filePathToSave: String
    ) {
        val configName = "TransportLayer_Eigenschaft8"
        for (androidSshClientTyp in listOf(
            AndroidSshClientTyp.TERMIUS,
            AndroidSshClientTyp.JUICE_SSH,
            AndroidSshClientTyp.CONNECT_BOT
        )) {
            val configGeneral = createDefaultConfig()
            configGeneral.outputDirectory += androidSshClientTyp.name + "_" + configName
            configGeneral.sulConfig.protocolStage = ProtocolStage.UNKNOWN
            configGeneral.sulConfig.customProtocolStageNameForGraph = "Transport-Layer"
            configGeneral.sulConfig.preLearnFingerprintAcceptance = false

            configGeneral.learnerConfig.equivCompleteExplorationMinDepth = 5
            configGeneral.learnerConfig.equivCompleteExplorationMaxDepth = 5
            configGeneral.learnerConfig.equivHappyFlowSuffixLength = 3

            configGeneral.learnerConfig.alternativeHappyFlowAlphabet = listOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.alphabet = listOf(
                //ServerMessages
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT,
                SshSymbol.MSG_USERAUTH_SUCCESS
            )

            configGeneral.sulConfig.stateNameAndSuccessorTransitions = listOf(
                StateNameAndSuccessorTransition("Protocol Version Exchanged", SshSymbol.MSG_KEXINIT),
                StateNameAndSuccessorTransition("KEX: Algorithms Negotiated", SshSymbol.MSG_KEX_ECDH_REPLY),
                StateNameAndSuccessorTransition("KEX: DH Group Negotiated", SshSymbol.MSG_NEWKEYS),
                StateNameAndSuccessorTransition("KEX: Keys Derived", SshSymbol.MSG_SERVICE_ACCEPT),
                StateNameAndSuccessorTransition("Transport Layer completed", SshSymbol.MSG_USERAUTH_SUCCESS),
                StateNameAndSuccessorTransition("Authentication Layer completed "),
            )
            when (androidSshClientTyp) {
                AndroidSshClientTyp.TERMIUS -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.JUICE_SSH -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 16
                }

                AndroidSshClientTyp.CONNECT_BOT -> {
                    setClientTypSpecific(configGeneral, androidSshClientTyp)
                    configGeneral.learnerConfig.repeatedQueriesDuringLearningWithMajorityCount = 64
                }

                else -> {}
            }
            safeFile(filePathToSave + "${androidSshClientTyp.name}_$configName", configGeneral)
        }
    }


    createTransportLayerConfig_Eigenschaft1347(outputDir)
    createTransportLayerConfig_Eigenschaft5(outputDir)
    createTransportLayerConfig_Eigenschaft2(outputDir)
    createTransportLayerConfig_Eigenschaft6(outputDir)
    createTransportLayerConfig_Eigenschaft8(outputDir)
}


fun main() {
    val outputDir = "./src/main/resources/"
    createConfigSchemaJson(outputDir)
    createDefaultConfigs(outputDir)
    createConfigForAnalysis(outputDir)
}