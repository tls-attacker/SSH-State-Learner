/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.api.SUL
import de.rub.nds.modifiablevariable.util.ArrayConverter
import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.NamedEcGroup
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType
import de.rub.nds.sshstatelearner.extraction.HappyFlowFactory
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.words.Word
import net.automatalib.words.WordBuilder
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.math.BigInteger

abstract class SshSul(
    val name: String,
    val timeout: Long = DEFAULT_SUL_TIMEOUT,
    val resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    val stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    val kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM
) : SUL<SshSymbol, ResponseFingerprint>, AutoCloseable {

    /**
     * The config of the SSH-Attacker.
     */
    protected lateinit var config: Config

    /**
     * The state of the SSH-Attacker.
     */
    protected lateinit var state: State

    /**
     * A list of SshSymbols that need to be executed within pre() to reach the defined protocol stage.
     */
    protected val preamble: Word<SshSymbol> = constructPreamble()

    /**
     * A list of all executed steps on the current SSH connection.
     */
    protected val executedSteps = mutableListOf<SshSymbol>()

    companion object {
        /**
         * Logger for the SshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()

        /**
         * A non-negative integer value indicating the timeout for symbol execution.
         */
        const val DEFAULT_SUL_TIMEOUT: Long = 1000

        /**
         * A non-negative integer value indicating the delay when resetting the SUL.
         */
        const val DEFAULT_SUL_RESET_DELAY: Long = 0

        /**
         * The default protocol stage to execute on
         */
        val DEFAULT_PROTOCOL_STAGE: ProtocolStage = ProtocolStage.TRANSPORT

        /**
         * The default key exchange algorithm
         */
        val DEFAULT_KEX_ALGORITHM: KeyExchangeAlgorithm = KeyExchangeAlgorithm.ECDH_SHA2_NISTP256
    }

    /**
     * Constructs a list of SshSymbols that need to be executed to reach the provided SSH protocol stage.
     *
     * @return List of SshSymbols whose execution lead to the provided SSH protocol stage.
     */
    private fun constructPreamble(): Word<SshSymbol> {
        var preamble: Word<SshSymbol> = Word.epsilon()
        if (stage == ProtocolStage.AUTHENTICATION || stage == ProtocolStage.CONNECTION) {
            preamble = preamble.concat(HappyFlowFactory.constructHappyFlow(ProtocolStage.TRANSPORT, kex))
        }
        if (stage == ProtocolStage.CONNECTION) {
            preamble = preamble.concat(HappyFlowFactory.constructHappyFlow(ProtocolStage.AUTHENTICATION, kex))
        }
        return preamble
    }

    /**
     * Set up the SSH SUL by instantiating a new SSH-Attacker config and state.
     */
    override fun pre() {
        config = Config.createConfig().apply {
            // TODO: Allow state initialization without specifying trace type
            workflowTraceType = WorkflowTraceType.KEX_INIT_ONLY
            stopActionsAfterDisconnect = false
            stopActionsAfterIOException = false
            clientSupportedKeyExchangeAlgorithms = listOf(kex)
            serviceName = "ssh-userauth"
            // TODO: Fix CTR
            clientSupportedEncryptionAlgorithmsClientToServer = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
            clientSupportedEncryptionAlgorithmsServerToClient = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
            userKeys = listOf(
                SshPublicKey(
                    PublicKeyFormat.ECDSA_SHA2_NISTP521,
                    CustomEcPublicKey(
                        PointFormatter.formatFromByteArray(
                            NamedEcGroup.SECP521R1,
                            ArrayConverter.hexStringToByteArray(
                                "04007a9a61317b93ec991102aea304" +
                                    "7641b3b91254d5267ac1bade8972db" +
                                    "7ee61dd0189d5663ff1988815e2632" +
                                    "7634465f38f12112db2caa87020528" +
                                    "e40091140810da01c643704d3bad15" +
                                    "88572e1eeb36080c25e307e99f5263" +
                                    "6c926c5c15eccaf5526ff2c79e3e5f" +
                                    "683be0bfa5bd806217b690fd6bbfcc" +
                                    "ca27cd82fd79bb194fccae7858"
                            )
                        ),
                        NamedEcGroup.SECP521R1
                    ),
                    CustomEcPrivateKey(
                        BigInteger(
                            "01cac52efb225c5321f43e80bd28ee" +
                                "e0c9f21297684305586bcc68dded8d" +
                                "dc2acb2554b015810c8913211a8238" +
                                "a0cb56aa9c2295143e62afa476b4a4" +
                                "4fad5fee4717",
                            16
                        ),
                        NamedEcGroup.SECP521R1
                    )
                )
            )
        }
    }

    /**
     * Tear down all stateful components of this SUL.
     */
    override fun post() {
        executedSteps.clear()
    }

    override fun close() { }

    fun majorityVote(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, count: Int): Word<ResponseFingerprint> {
        val voteList = mutableListOf<Word<ResponseFingerprint>>()
        for (i in 0 until count) {
            val wordBuilder = WordBuilder<ResponseFingerprint>()
            pre()
            for (symbol in prefix) {
                step(symbol)
            }
            for (symbol in suffix) {
                wordBuilder.append(step(symbol))
            }
            post()
            voteList.add(wordBuilder.toWord())
        }
        return majorityElement(voteList)
    }

    private fun majorityElement(words: List<Word<ResponseFingerprint>>): Word<ResponseFingerprint> {
        var majorityWord: Word<ResponseFingerprint> = words[0]
        var counter = 1
        for (word in words) {
            if (counter == 0) {
                majorityWord = word
                counter = 1
            } else if (word == majorityWord) {
                counter++
            } else {
                counter--
            }
        }
        return majorityWord
    }
}
