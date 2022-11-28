/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.extraction

import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory
import de.rub.nds.modifiablevariable.integer.ModifiableInteger
import de.rub.nds.modifiablevariable.string.ModifiableString
import de.rub.nds.modifiablevariable.string.StringModificationFactory
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage
import de.rub.nds.sshstatelearner.algorithms.symbols.AbstractSshSymbol
import de.rub.nds.sshstatelearner.algorithms.symbols.toSymbol

enum class SshSymbol(val symbolImpl: AbstractSshSymbol) {
    /*
     * SSH transport protocol symbols
     */
    MSG_DISCONNECT(DisconnectMessage().toSymbol()),
    MSG_IGNORE(IgnoreMessage().toSymbol()),
    MSG_UNIMPLEMENTED(UnimplementedMessage().toSymbol()),
    MSG_DEBUG(DebugMessage().toSymbol()),
    MSG_SERVICE_REQUEST(ServiceRequestMessage().toSymbol()),
    MSG_SERVICE_ACCEPT(ServiceAcceptMessage().toSymbol()),
    MSG_KEXINIT(KeyExchangeInitMessage().toSymbol()),
    MSG_NEWKEYS(NewKeysMessage().toSymbol()),
    MSG_KEX_DH_GEX_REQUEST(DhGexKeyExchangeRequestMessage().toSymbol()),
    MSG_KEX_DH_GEX_REQUEST_OLD(DhGexKeyExchangeOldRequestMessage().toSymbol()),
    MSG_KEX_DH_GEX_GROUP(DhGexKeyExchangeGroupMessage().toSymbol()),
    MSG_KEX_DH_GEX_INIT(DhGexKeyExchangeInitMessage().toSymbol()),
    MSG_KEX_DH_GEX_REPLY(DhGexKeyExchangeReplyMessage().toSymbol()),
    MSG_KEXDH_INIT(DhKeyExchangeInitMessage().toSymbol()),
    MSG_KEXDH_REPLY(DhKeyExchangeReplyMessage().toSymbol()),
    MSG_KEX_ECDH_INIT(EcdhKeyExchangeInitMessage().toSymbol()),
    MSG_KEX_ECDH_REPLY(EcdhKeyExchangeReplyMessage().toSymbol()),

    /*
     * SSH authentication protocol symbols
     */
    MSG_USERAUTH_REQUEST_PASSWD_VALID(UserAuthPasswordMessage().toSymbol()),

    // OpenSSH sends SSH_MSG_USERAUTH_FAILURE after a delay of approx. 2 seconds after trying to authenticate
    // with an invalid password. The increase in the retrieve delay ensures that the message is retrieved.
    MSG_USERAUTH_REQUEST_PASSWD_INVALID(
        UserAuthPasswordMessage().apply {
            passwordLength = ModifiableInteger().apply {
                modification = IntegerModificationFactory.explicitValue(14)
            }
            password = ModifiableString().apply {
                modification = StringModificationFactory.explicitValue("Wrong password")
            }
        }.toSymbol(3000)
    ),
    MSG_USERAUTH_SUCCESS(UserAuthSuccessMessage().toSymbol()),
    MSG_USERAUTH_FAILURE(UserAuthFailureMessage().toSymbol()),
    MSG_USERAUTH_BANNER(UserAuthBannerMessage().toSymbol()),

    /*
     * SSH connection protocol symbols
     */
    MSG_REQUEST_SUCCESS(GlobalRequestSuccessMessage().toSymbol()),
    MSG_REQUEST_FAILURE(GlobalRequestFailureMessage().toSymbol()),
    MSG_CHANNEL_OPEN(ChannelOpenMessage().toSymbol()),
    MSG_CHANNEL_OPEN_CONFIRMATION(ChannelOpenConfirmationMessage().toSymbol()),
    MSG_CHANNEL_OPEN_FAILURE(ChannelOpenFailureMessage().toSymbol()),
    MSG_CHANNEL_WINDOW_ADJUST(ChannelWindowAdjustMessage().toSymbol()),
    MSG_CHANNEL_EOF(ChannelEofMessage().toSymbol()),
    MSG_CHANNEL_CLOSE(ChannelCloseMessage().toSymbol()),
    MSG_CHANNEL_REQUEST_EXEC(ChannelRequestExecMessage().toSymbol()),
    MSG_CHANNEL_SUCCESS(ChannelSuccessMessage().toSymbol()),
    MSG_CHANNEL_FAILURE(ChannelFailureMessage().toSymbol())
}
