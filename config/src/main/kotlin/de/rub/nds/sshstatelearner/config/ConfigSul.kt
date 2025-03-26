package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonSubTypes.Type
import com.fasterxml.jackson.annotation.JsonTypeInfo
import de.rub.nds.sshattacker.core.constants.ConnectionDirection
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.analysis.classifier.StateNameAndSuccessorTransition
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.sul.SshSul

/**
 * Abstract configuration class that contains all attributes that are essential for every SUL.
 */

@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = "type"
)
@JsonSubTypes(
    value =
    [
        Type(name = "configServerSul", value = ConfigServerSul::class),
        Type(name = "configClientSul", value = ConfigClientSul::class),
        Type(name = "configAndroidClientSul", value = ConfigAndroidClientSul::class)
    ]
)
abstract class ConfigSul(
    @field:JsonPropertyDescription("Human-readable name of the target SSH server (i. e. SSH server implementation and version)")
    @field:JsonProperty(defaultValue = "Unspecified SSH Server/Client")
    var name: String = "Unspecified SSH Server/Client",


    @field:JsonPropertyDescription("Timeout in milliseconds when executing a single symbol")
    @field:JsonProperty(defaultValue = "50")
    var timeout: Long = SshSul.DEFAULT_SUL_TIMEOUT,


    @field:JsonPropertyDescription("Delay in milliseconds during reset of a SUL instance")
    @field:JsonProperty(defaultValue = "0")
    var resetDelay: Long = SshSul.DEFAULT_SUL_RESET_DELAY,


    @field:JsonPropertyDescription("The SSH protocol stage whose state machine is to be extracted")
    @field:JsonProperty(defaultValue = "TRANSPORT")
    var protocolStage: ProtocolStage = SshSul.DEFAULT_PROTOCOL_STAGE,


    @field:JsonPropertyDescription("Changes stage names in the graph. It is only used if protocolStage==UNKNOWN\"")
    @field:JsonProperty(defaultValue = "")
    var customProtocolStageNameForGraph: String = "",


    @field:JsonPropertyDescription("Possibility to mark a different happy flow in the graph. It is only used if protocolStage==UNKNOWN")
    @field:JsonProperty(defaultValue = "[]")
    var stateNameAndSuccessorTransitions: List<StateNameAndSuccessorTransition> = emptyList(),


    @field:JsonPropertyDescription("The SSH key exchange method to use. If the alphabet is not specified and the TRANSPORT protocol stage is about to be learned, it derives the alphabet from the provided kex algorithm")
    @field:JsonProperty(defaultValue = "ECDH_SHA2_NISTP521")
    var kexAlgorithm: KeyExchangeAlgorithm = SshSul.DEFAULT_KEX_ALGORITHM,


    @field:JsonPropertyDescription("If set to true, the SUL will offer the strict key exchange protocol extension.")
    @field:JsonProperty(defaultValue = "false")
    var strictKex: Boolean = SshSul.DEFAULT_STRICT_KEX_ENABLED,


    @field:JsonPropertyDescription("A comma-separated list of SshSymbol names to use as the alphabet. It is only used if protocolStage==UNKNOWN")
    @field:JsonProperty(defaultValue = "[]")
    var alphabet: List<SshSymbol> = emptyList(),


    @field:JsonPropertyDescription("Type under test")
    @field:JsonProperty(defaultValue = "SERVER")
    var sulType: SulType = SulType.SERVER,


    @field:JsonPropertyDescription("This attribute allows the SSH client to automatically accept the server's fingerprint before initiating the learning process")
    @field:JsonProperty(defaultValue = "true")
    var preLearnFingerprintAcceptance: Boolean = true,


    @field:JsonPropertyDescription("Activates the encryption after receiving or sending the NewKeys message. BOTH -> Receive,Send | SEND -> Send only | Receive -> Receive only")
    @field:JsonProperty(defaultValue = "BOTH")
    var enableEncryptionOnNewKeysMessage: ConnectionDirection = ConnectionDirection.BOTH,
)