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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshstatelearner.exceptions.IllegalKeyExchangeException
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet

/**
 * This object is capable of constructing the SSH alphabet given a protocol stage as well as a key exchange algorithm
 * to use. The receive delay of a single symbol may also be specified with the corresponding parameter.
 */
object AlphabetFactory {
    /**
     * Constructs an array of symbols to use with the given key exchange algorithm.
     *
     * @param kex The key exchange algorithm to construct the symbols for.
     * @param receiveDelay The receive delay for a single message symbol.
     * @return An array of symbol to use with the given key exchange algorithm.
     */
    private fun constructKexSymbols(kex: KeyExchangeAlgorithm, receiveDelay: Long): Array<out SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                DhGexKeyExchangeRequestMessage().toSymbol(receiveDelay),
                DhGexKeyExchangeOldRequestMessage().toSymbol(receiveDelay),
                DhGexKeyExchangeInitMessage().toSymbol(receiveDelay)
            )
            KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                DhKeyExchangeInitMessage().toSymbol(receiveDelay)
            )
            KeyExchangeFlowType.ECDH -> arrayOf(
                EcdhKeyExchangeInitMessage().toSymbol(receiveDelay)
            )
            KeyExchangeFlowType.ECMQV -> TODO("ECMQV kex algorithm is not yet implemented in SSH-Attacker")
            KeyExchangeFlowType.RSA -> TODO("RSA kex algorithm is not yet implemented in SSH-Attacker")
            null -> throw IllegalKeyExchangeException("Unable to construct kex symbols for extension info - ext-info-s and ext-info-c are no valid kex algorithms")
        }
    }

    /**
     * Constructs the alphabet given a protocol stage and key exchange algorithm. The receive delay of a single message
     * symbol may also be specified.
     *
     * @param stage The protocol stage to construct the alphabet for.
     * @param kex The key exchange algorithm to construct the alphabet for. If stage is not equal to TRANSPORT,
     *            this parameter does not influence the resulting alphabet.
     * @param receiveDelay The receive delay for a single message symbol. If omitted, a default value will be used.
     * @return An alphabet with valid SSH symbols to use within the given protocol stage and key exchange algorithm.
     */
    fun construct(
        stage: ProtocolStage = ProtocolStage.TRANSPORT,
        kex: KeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
        receiveDelay: Long = SshSymbol.DEFAULT_RECEIVE_DELAY
    ): Alphabet<SshSymbol> {
        return when (stage) {
            ProtocolStage.TRANSPORT -> ListAlphabet(
                listOf(
                    VersionExchangeMessage().toSymbol(receiveDelay),
                    KeyExchangeInitMessage().toSymbol(receiveDelay),
                    *constructKexSymbols(kex, receiveDelay),
                    NewKeysMessage().toSymbol(receiveDelay),
                    ServiceRequestMessage().toSymbol(receiveDelay)
                )
            )
            ProtocolStage.AUTHENTICATION -> ListAlphabet(
                listOf(
                    UserAuthPasswordMessage().toSymbol(receiveDelay),
                    UserAuthFailureMessage().toSymbol(receiveDelay),
                    UserAuthSuccessMessage().toSymbol(receiveDelay),
                    UserAuthBannerMessage().toSymbol(receiveDelay)
                )
            )
            ProtocolStage.CONNECTION -> ListAlphabet(
                listOf(
                    ChannelEofMessage().toSymbol(receiveDelay),
                    ChannelFailureMessage().toSymbol(receiveDelay),
                    ChannelOpenMessage().toSymbol(receiveDelay),
                    ChannelRequestExecMessage().toSymbol(receiveDelay),
                    ChannelWindowAdjustMessage().toSymbol(receiveDelay)
                )
            )
        }
    }
}
