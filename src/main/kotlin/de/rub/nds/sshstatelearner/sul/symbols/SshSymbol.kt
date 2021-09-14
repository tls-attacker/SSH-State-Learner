/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

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
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestSuccessMessage
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
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage

enum class SshSymbol(val symbolImpl: AbstractSshSymbolImpl) {
    /*
     * SSH transport protocol symbols
     */
    VERSION_EXCHANGE(VersionExchangeMessage().toSymbolImpl()),
    MSG_DISCONNECT(DisconnectMessage().toSymbolImpl()),
    MSG_IGNORE(IgnoreMessage().toSymbolImpl()),
    MSG_UNIMPLEMENTED(UnimplementedMessage().toSymbolImpl()),
    MSG_DEBUG(DebugMessage().toSymbolImpl()),
    MSG_SERVICE_REQUEST(ServiceRequestMessage().toSymbolImpl()),
    MSG_SERVICE_ACCEPT(ServiceAcceptMessage().toSymbolImpl()),
    MSG_KEXINIT(KeyExchangeInitMessage().toSymbolImpl()),
    MSG_NEWKEYS(NewKeysMessage().toSymbolImpl()),
    MSG_KEX_DH_GEX_REQUEST(DhGexKeyExchangeRequestMessage().toSymbolImpl()),
    MSG_KEX_DH_GEX_REQUEST_OLD(DhGexKeyExchangeOldRequestMessage().toSymbolImpl()),
    MSG_KEX_DH_GEX_GROUP(DhGexKeyExchangeGroupMessage().toSymbolImpl()),
    MSG_KEX_DH_GEX_INIT(DhGexKeyExchangeInitMessage().toSymbolImpl()),
    MSG_KEX_DH_GEX_REPLY(DhGexKeyExchangeReplyMessage().toSymbolImpl()),
    MSG_KEXDH_INIT(DhKeyExchangeInitMessage().toSymbolImpl()),
    MSG_KEXDH_REPLY(DhKeyExchangeReplyMessage().toSymbolImpl()),
    MSG_KEX_ECDH_INIT(EcdhKeyExchangeInitMessage().toSymbolImpl()),
    MSG_KEX_ECDH_REPLY(EcdhKeyExchangeReplyMessage().toSymbolImpl()),
    /*
     * SSH authentication protocol symbols
     */
    MSG_USERAUTH_REQUEST_PASSWD_VALID(UserAuthPasswordMessage().toSymbolImpl()),
    // OpenSSH sends SSH_MSG_USERAUTH_FAILURE after a delay of approx. 2 seconds after trying to authenticate
    // with an invalid password. The increase in the retrieve delay ensures that the message is retrieved.
    MSG_USERAUTH_REQUEST_PASSWD_INVALID(UserAuthPasswordMessage().apply {
        passwordLength = ModifiableInteger().apply {
            modification = IntegerModificationFactory.explicitValue(14)
        }
        password = ModifiableString().apply {
            modification = StringModificationFactory.explicitValue("Wrong password")
        }
    }.toSymbolImpl(3000)),
    MSG_USERAUTH_SUCCESS(UserAuthSuccessMessage().toSymbolImpl()),
    MSG_USERAUTH_FAILURE(UserAuthFailureMessage().toSymbolImpl()),
    MSG_USERAUTH_BANNER(UserAuthBannerMessage().toSymbolImpl()),
    /*
     * SSH connection protocol symbols
     */
    MSG_REQUEST_SUCCESS(RequestSuccessMessage().toSymbolImpl()),
    MSG_REQUEST_FAILURE(RequestFailureMessage().toSymbolImpl()),
    MSG_CHANNEL_OPEN(ChannelOpenMessage().toSymbolImpl()),
    MSG_CHANNEL_OPEN_CONFIRMATION(ChannelOpenConfirmationMessage().toSymbolImpl()),
    MSG_CHANNEL_OPEN_FAILURE(ChannelOpenFailureMessage().toSymbolImpl()),
    MSG_CHANNEL_WINDOW_ADJUST(ChannelWindowAdjustMessage().toSymbolImpl()),
    MSG_CHANNEL_EOF(ChannelEofMessage().toSymbolImpl()),
    MSG_CHANNEL_CLOSE(ChannelCloseMessage().toSymbolImpl()),
    MSG_CHANNEL_REQUEST_EXEC(ChannelRequestExecMessage().toSymbolImpl()),
    MSG_CHANNEL_SUCCESS(ChannelSuccessMessage().toSymbolImpl()),
    MSG_CHANNEL_FAILURE(ChannelFailureMessage().toSymbolImpl())
}
