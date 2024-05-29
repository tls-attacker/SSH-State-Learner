package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import de.rub.nds.sshstatelearner.constants.ExecutorType

data class ConfigGeneral(
    @field:JsonPropertyDescription("Folder to output the extracted state machine to")
    @field:JsonProperty(defaultValue = "out/")
    var outputDirectory: String = "out/",

    @field:JsonPropertyDescription("Executor to use")
    @field:JsonProperty(defaultValue = "NETWORK")
    var executorType: ExecutorType = ExecutorType.NETWORK,

    @field:JsonPropertyDescription("Bundling of all Learning options")
    var learnerConfig: ConfigLearner = ConfigLearner(),

    @field:JsonPropertyDescription("Bundling of all Sul options")
    @field:JsonProperty(defaultValue = "ConfigServerSul")
    var sulConfig: ConfigSul = ConfigServerSul()
)