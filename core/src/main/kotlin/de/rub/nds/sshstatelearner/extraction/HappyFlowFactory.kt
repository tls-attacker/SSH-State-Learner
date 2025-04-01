/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.extraction

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import net.automatalib.word.Word

/**
 * This object is capable of constructing happy flows for different SSH protocol stages. A happy flow is considered any
 * valid combination of input symbols that lead to a desired output. For the TRANSPORT protocol, this is a successful
 * key exchange, for the AUTHENTICATION protocol a successful authentication and for the CONNECTION protocol a successful
 * command execution.
 */
object HappyFlowFactory {

    /**
     * Constructs an array of key exchange specific symbols based on the flow type of the selected key exchange algorithm.
     *
     * @param sulType Specifies whether the symbols are constructed for a client or a server.
     * @param kex The selected key exchange algorithm.
     * @return An array of key exchange specific symbols in valid order.
     */
    private fun constructKexFlow(sulType: SulType, kex: KeyExchangeAlgorithm): Array<SshSymbol> {
        return if (sulType == SulType.SERVER) when (kex.flowType) {
                KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                    SshSymbol.MSG_KEX_DH_GEX_REQUEST,
                    SshSymbol.MSG_KEX_DH_GEX_INIT
                )
                KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                    SshSymbol.MSG_KEXDH_INIT
                )
                KeyExchangeFlowType.ECDH -> arrayOf(
                    SshSymbol.MSG_KEX_ECDH_INIT
                )
                KeyExchangeFlowType.HYBRID -> arrayOf(
                    SshSymbol.MSG_KEX_HBR_INIT
                )
                KeyExchangeFlowType.RSA -> arrayOf(
                    SshSymbol.MSG_KEX_RSA_SECRET
                )
                else -> throw NotImplementedException("Key exchange algorithm flow type ${kex.flowType} is not yet supported by SSH-State-Learner")
            }
            else when (kex.flowType) {
                KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                    SshSymbol.MSG_KEX_DH_GEX_GROUP,
                    SshSymbol.MSG_KEX_DH_GEX_REPLY
                )
                KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                    SshSymbol.MSG_KEXDH_REPLY
                )
                KeyExchangeFlowType.ECDH -> arrayOf(
                    SshSymbol.MSG_KEX_ECDH_REPLY
                )
                KeyExchangeFlowType.HYBRID -> arrayOf(
                    SshSymbol.MSG_KEX_HBR_REPLY
                )
                KeyExchangeFlowType.RSA -> arrayOf(
                    SshSymbol.MSG_KEX_RSA_PUBKEY,
                    SshSymbol.MSG_KEX_RSA_DONE
                )
                else -> throw NotImplementedException("Key exchange algorithm flow type ${kex.flowType} is not yet supported by SSH-State-Learner")
            }
    }

    /**
     * Constructs a happy flow which, applied on a fresh SUL oracle, lead to a desired output.
     *
     * @param sulType Specifies whether the happy flow is constructed for a client or a server.
     * @param stage The protocol stage to construct a happy flow for.
     * @param kex The selected key exchange method to construct a happy flow for.
     * @return The word representing a happy flow within the provided protocol stage and key exchange algorithm.
     */
    fun constructHappyFlow(sulType: SulType, stage: ProtocolStage, kex: KeyExchangeAlgorithm): Word<SshSymbol> {
        return if (sulType == SulType.SERVER) when (stage) {
            ProtocolStage.TRANSPORT -> Word.fromSymbols(
                SshSymbol.MSG_KEXINIT,
                *constructKexFlow(sulType, kex),
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_REQUEST_USERAUTH
            )
            ProtocolStage.TRANSPORT_KEX -> Word.fromSymbols(
                SshSymbol.MSG_KEXINIT,
                *constructKexFlow(sulType, kex),
                SshSymbol.MSG_NEWKEYS
            )
            ProtocolStage.AUTHENTICATION -> Word.fromSymbols(
                SshSymbol.MSG_USERAUTH_REQUEST_PASSWORD
            )
            ProtocolStage.CONNECTION -> Word.fromSymbols(
                SshSymbol.MSG_CHANNEL_OPEN_SESSION,
                SshSymbol.MSG_CHANNEL_REQUEST_EXEC
            )
            else -> throw IllegalArgumentException("Unable to construct happy flow for protocol stage: $stage")
        }
        else when (stage) {
            ProtocolStage.TRANSPORT -> Word.fromSymbols(
                SshSymbol.MSG_KEXINIT,
                *constructKexFlow(sulType, kex),
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT
            )
            ProtocolStage.TRANSPORT_KEX -> Word.fromSymbols(
                SshSymbol.MSG_KEXINIT,
                *constructKexFlow(sulType, kex),
                SshSymbol.MSG_NEWKEYS,
            )
            ProtocolStage.AUTHENTICATION -> Word.fromSymbols(
                SshSymbol.MSG_USERAUTH_SUCCESS
            )
            ProtocolStage.CONNECTION -> Word.fromSymbols(
                SshSymbol.MSG_CHANNEL_OPEN_CONFIRMATION,
                SshSymbol.MSG_CHANNEL_SUCCESS
            )
            else -> throw IllegalArgumentException("Unable to construct happy flow for protocol stage: $stage")
        }
    }
}