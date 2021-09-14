/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

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
     * Returns an array of symbols to use with the given key exchange algorithm.
     *
     * @param kex The key exchange algorithm to construct the symbols for.
     * @return An array of symbol to use with the given key exchange algorithm.
     */
    private fun getKexSymbols(kex: KeyExchangeAlgorithm): Array<out SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                SshSymbol.MSG_KEX_DH_GEX_REQUEST,
                SshSymbol.MSG_KEX_DH_GEX_REQUEST_OLD,
                SshSymbol.MSG_KEX_DH_GEX_INIT
            )
            KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                SshSymbol.MSG_KEXDH_INIT
            )
            KeyExchangeFlowType.ECDH -> arrayOf(
                SshSymbol.MSG_KEX_ECDH_INIT
            )
            KeyExchangeFlowType.ECMQV -> TODO("ECMQV kex algorithm is not yet implemented in SSH-Attacker")
            KeyExchangeFlowType.RSA -> TODO("RSA kex algorithm is not yet implemented in SSH-Attacker")
            null -> throw IllegalKeyExchangeException("Unable to get kex symbols for extension info - ext-info-s and ext-info-c are no valid kex algorithms")
        }
    }

    /**
     * Constructs the alphabet given a protocol stage and key exchange algorithm.
     *
     * @param stage The protocol stage to construct the alphabet for.
     * @param kex The key exchange algorithm to construct the alphabet for. If stage is not equal to TRANSPORT,
     *            this parameter does not influence the resulting alphabet.
     * @return An alphabet with valid SSH symbols to use within the given protocol stage and key exchange algorithm.
     */
    fun construct(
        stage: ProtocolStage = ProtocolStage.TRANSPORT,
        kex: KeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256
    ): Alphabet<SshSymbol> {
        return when (stage) {
            ProtocolStage.TRANSPORT -> ListAlphabet(
                listOf(
                    SshSymbol.VERSION_EXCHANGE,
                    SshSymbol.MSG_KEXINIT,
                    *getKexSymbols(kex),
                    SshSymbol.MSG_NEWKEYS,
                    SshSymbol.MSG_SERVICE_REQUEST
                )
            )
            ProtocolStage.AUTHENTICATION -> ListAlphabet(
                listOf(
                    SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_VALID,
                    SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_INVALID,
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
                    SshSymbol.MSG_CHANNEL_OPEN,
                    SshSymbol.MSG_CHANNEL_REQUEST_EXEC,
                    SshSymbol.MSG_CHANNEL_WINDOW_ADJUST
                )
            )
        }
    }
}
