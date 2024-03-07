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
import de.rub.nds.sshstatelearner.exceptions.IllegalKeyExchangeException
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet

/**
 * This object is capable of constructing the SSH alphabet given a protocol stage as well as a key exchange algorithm to use.
 */
object AlphabetFactory {
    /**
     * Returns an array of symbols for clients to use with the given key exchange algorithm.
     *
     * @param kex The key exchange algorithm to construct the symbols for.
     * @return An array of symbol to use with the given key exchange algorithm.
     */
    private fun getKexSymbolsForClient(kex: KeyExchangeAlgorithm): List<SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> listOf(
                SshSymbol.MSG_KEX_DH_GEX_REQUEST,
                SshSymbol.MSG_KEX_DH_GEX_REQUEST_OLD,
                SshSymbol.MSG_KEX_DH_GEX_INIT
            )

            KeyExchangeFlowType.DIFFIE_HELLMAN -> listOf(
                SshSymbol.MSG_KEXDH_INIT
            )

            KeyExchangeFlowType.ECDH -> listOf(
                SshSymbol.MSG_KEX_ECDH_INIT
                )

            KeyExchangeFlowType.RSA -> listOf(
                SshSymbol.MSG_KEX_RSA_SECRET
            )

            KeyExchangeFlowType.HYBRID -> listOf(
                SshSymbol.MSG_KEX_HBR_INIT
            )
            KeyExchangeFlowType.ECMQV -> TODO("ECMQV kex algorithm is not yet implemented in SSH-Attacker")
            null -> throw IllegalKeyExchangeException("Unable to get kex symbols for extension info - ext-info-s and ext-info-c are no valid kex algorithms")
        }
    }

    /**
     * {@see getKexSymbolsForClient} but for Servers
     */
    private fun getKexSymbolsForServer(kex: KeyExchangeAlgorithm): List<SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> listOf(
                SshSymbol.MSG_KEX_DH_GEX_GROUP,
                SshSymbol.MSG_KEX_DH_GEX_REPLY
            )

            KeyExchangeFlowType.DIFFIE_HELLMAN -> listOf(
                SshSymbol.MSG_KEXDH_REPLY
            )

            KeyExchangeFlowType.ECDH -> listOf(
                SshSymbol.MSG_KEX_ECDH_REPLY
            )

            KeyExchangeFlowType.RSA -> listOf(
                SshSymbol.MSG_KEX_RSA_PUBKEY,
                SshSymbol.MSG_KEX_RSA_DONE
            )

            KeyExchangeFlowType.HYBRID -> listOf(
                SshSymbol.MSG_KEX_HBR_REPLY
            )

            KeyExchangeFlowType.ECMQV -> TODO("ECMQV kex algorithm is not yet implemented in SSH-Attacker")
            null -> throw IllegalKeyExchangeException("Unable to get kex symbols for extension info - ext-info-s and ext-info-c are no valid kex algorithms")
        }
    }

    /**
     * Special case for isClientAlphabet == true: {@see construct}
     */
    private fun getProtocolStageAndKexSymbolsForClient(
        stage: ProtocolStage,
        kex: KeyExchangeAlgorithm
    ): Alphabet<SshSymbol> {
        return when (stage) {
            ProtocolStage.TRANSPORT -> ListAlphabet(
                //TODO: enthält aktuelle nur Client Symbole, vielleicht alle reinpacken... -> Client und Server Unterscheidung fällt weg.
                listOf(
                    SshSymbol.MSG_KEXINIT,
                    *getKexSymbolsForClient(kex).toTypedArray(),
                    SshSymbol.MSG_NEWKEYS,
                    SshSymbol.MSG_SERVICE_REQUEST_USERAUTH
                )
            )

            ProtocolStage.AUTHENTICATION -> ListAlphabet(
                listOf(
                    SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_VALID,
                    SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_INVALID,
                    SshSymbol.MSG_USERAUTH_REQUEST_PUBKEY_VALID,
                    SshSymbol.MSG_USERAUTH_SUCCESS,
                    SshSymbol.MSG_USERAUTH_FAILURE,
                    SshSymbol.MSG_USERAUTH_BANNER
                )
            )

            ProtocolStage.CONNECTION -> ListAlphabet(
                listOf(
                    SshSymbol.MSG_CHANNEL_EOF,
                    SshSymbol.MSG_CHANNEL_SUCCESS,
                    SshSymbol.MSG_CHANNEL_FAILURE,
                    SshSymbol.MSG_CHANNEL_OPEN_SESSION,
                    SshSymbol.MSG_CHANNEL_REQUEST_EXEC,
                    SshSymbol.MSG_CHANNEL_WINDOW_ADJUST
                )
            )
        }
    }

    /**
     * Special case for isClientAlphabet == false: {@see construct}
     */
    private fun getProtocolStageAndKexSymbolsForServer(
        stage: ProtocolStage,
        kex: KeyExchangeAlgorithm
    ): Alphabet<SshSymbol> {
        return when (stage) {
            ProtocolStage.TRANSPORT -> ListAlphabet(
                listOf(
                    SshSymbol.MSG_KEXINIT,
                    *getKexSymbolsForServer(kex).toTypedArray(),
                    SshSymbol.MSG_NEWKEYS,
                    SshSymbol.MSG_SERVICE_ACCEPT,
                )
            )

            ProtocolStage.AUTHENTICATION -> ListAlphabet(
                listOf(
                    SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_VALID,
                    SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_INVALID,
                    SshSymbol.MSG_USERAUTH_REQUEST_PUBKEY_VALID,
                    SshSymbol.MSG_USERAUTH_SUCCESS,
                    SshSymbol.MSG_USERAUTH_FAILURE,
                    SshSymbol.MSG_USERAUTH_BANNER
                )
            )

            ProtocolStage.CONNECTION -> ListAlphabet(
                listOf(
                    SshSymbol.MSG_CHANNEL_EOF,
                    SshSymbol.MSG_CHANNEL_SUCCESS,
                    SshSymbol.MSG_CHANNEL_FAILURE,
                    SshSymbol.MSG_CHANNEL_OPEN_SESSION,
                    SshSymbol.MSG_CHANNEL_REQUEST_EXEC,
                    SshSymbol.MSG_CHANNEL_WINDOW_ADJUST
                )
            )
        }
    }

    /**
     * Constructs the alphabet given a protocol stage and key exchange algorithm for client or server.
     *
     * @param stage The protocol stage to construct the alphabet for.
     * @param kex The key exchange algorithm to construct the alphabet for. If stage is not equal to TRANSPORT,
     *            this parameter does not influence the resulting alphabet.
     * @param isClientAlphabet If true, the client alphabet is returned.
     *                 If true, the server alphabet is returned.
     * @return An alphabet with valid SSH symbols to use within the given protocol stage and key exchange algorithm.
     */
    fun construct(stage: ProtocolStage, kex: KeyExchangeAlgorithm, isClientAlphabet: Boolean): Alphabet<SshSymbol> {
        return if (isClientAlphabet) {
            getProtocolStageAndKexSymbolsForClient(stage, kex)
        } else {
            getProtocolStageAndKexSymbolsForServer(stage, kex)
        }
    }
}
