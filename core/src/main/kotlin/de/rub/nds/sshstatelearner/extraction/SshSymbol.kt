/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.extraction

import de.rub.nds.modifiablevariable.util.Modifiable
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage
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
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.SshContext

enum class SshSymbol(
    val messageCreator: () -> ProtocolMessage<*>,
    private val afterPrepare: ((message: ProtocolMessage<*>, context: SshContext) -> Unit)? = null
) {
    /*
     * SSH transport protocol symbols
     */
    MSG_VERSION_EXCHANGE({ VersionExchangeMessage() }),
    MSG_DISCONNECT({ DisconnectMessage() }),
    MSG_IGNORE({ IgnoreMessage() }),
    MSG_UNIMPLEMENTED({ UnimplementedMessage() }, { message, context ->
        (message as UnimplementedMessage).apply {
            setSequenceNumber(context.readSequenceNumber - 1)
        }
    }),
    MSG_DEBUG({ DebugMessage() }),
    MSG_SERVICE_REQUEST_USERAUTH({
        ServiceRequestMessage()
    }, { message, _ ->
        (message as ServiceRequestMessage).apply {
            serviceNameLength = Modifiable.explicit(12)
            serviceName = Modifiable.explicit("ssh-userauth")
        }
    }),
    MSG_SERVICE_ACCEPT({ ServiceAcceptMessage() }),
    MSG_EXT_INFO({ ExtensionInfoMessage() }),
    MSG_NEWCOMPRESS({ NewCompressMessage() }),
    MSG_KEXINIT({ KeyExchangeInitMessage() }),
    MSG_KEXINIT_EMPTY({ KeyExchangeInitMessage() },
        { message, _ -> (message as KeyExchangeInitMessage).apply { setKeyExchangeAlgorithms(arrayOf(), true) } }),
    MSG_NEWKEYS({ NewKeysMessage() }),
    MSG_KEX_DH_GEX_REQUEST({ DhGexKeyExchangeRequestMessage() }),
    MSG_KEX_DH_GEX_REQUEST_OLD({ DhGexKeyExchangeOldRequestMessage() }),
    MSG_KEX_DH_GEX_GROUP({ DhGexKeyExchangeGroupMessage() }),
    MSG_KEX_DH_GEX_INIT({ DhGexKeyExchangeInitMessage() }),
    MSG_KEX_DH_GEX_REPLY({ DhGexKeyExchangeReplyMessage() }),
    MSG_KEXDH_INIT({ DhKeyExchangeInitMessage() }),
    MSG_KEXDH_REPLY({ DhKeyExchangeReplyMessage() }),
    MSG_KEX_ECDH_INIT({ EcdhKeyExchangeInitMessage() }),
    MSG_KEX_ECDH_REPLY({ EcdhKeyExchangeReplyMessage() }),
    MSG_KEX_RSA_PUBKEY({ RsaKeyExchangePubkeyMessage() }),
    MSG_KEX_RSA_SECRET({ RsaKeyExchangeSecretMessage() }),
    MSG_KEX_RSA_DONE({ RsaKeyExchangeDoneMessage() }),
    MSG_KEX_HBR_INIT({ HybridKeyExchangeInitMessage() }),
    MSG_KEX_HBR_REPLY({ HybridKeyExchangeReplyMessage() }),
    /*
     * SSH authentication protocol symbols
     */
    MSG_USERAUTH_REQUEST_PASSWD_VALID({ UserAuthPasswordMessage() }),
    MSG_USERAUTH_REQUEST_PASSWD_INVALID({
        UserAuthPasswordMessage()
    }, { message, _ ->
        (message as UserAuthPasswordMessage).apply {
            passwordLength = Modifiable.explicit(14)
            password = Modifiable.explicit("Wrong password")
        }
    }),
    MSG_USERAUTH_REQUEST_PUBKEY_VALID({ UserAuthPubkeyMessage() }),
    MSG_USERAUTH_SUCCESS({ UserAuthSuccessMessage() }),
    MSG_USERAUTH_FAILURE({ UserAuthFailureMessage() }),
    MSG_USERAUTH_BANNER({ UserAuthBannerMessage() }),
    MSG_SERVICE_REQUEST_CONNECTION({
        ServiceRequestMessage()
    }, { message, _ ->
        (message as ServiceRequestMessage).apply {
            serviceNameLength = Modifiable.explicit(14)
            serviceName = Modifiable.explicit("ssh-connection")
        }
    }),

    /*
     * SSH connection protocol symbols
     */
    MSG_REQUEST_SUCCESS({ GlobalRequestSuccessMessage() }),
    MSG_REQUEST_FAILURE({ GlobalRequestFailureMessage() }),
    MSG_CHANNEL_OPEN_SESSION({ ChannelOpenSessionMessage() }),
    MSG_CHANNEL_OPEN_CONFIRMATION({ ChannelOpenConfirmationMessage() }),
    MSG_CHANNEL_OPEN_FAILURE({ ChannelOpenFailureMessage() }),
    MSG_CHANNEL_WINDOW_ADJUST({ ChannelWindowAdjustMessage() }),
    MSG_CHANNEL_EOF({ ChannelEofMessage() }),
    MSG_CHANNEL_CLOSE({ ChannelCloseMessage() }),
    MSG_CHANNEL_REQUEST_EXEC({ ChannelRequestExecMessage() }),
    MSG_CHANNEL_SUCCESS({ ChannelSuccessMessage() }),
    MSG_CHANNEL_FAILURE({ ChannelFailureMessage() }),

    /*
     * Unknown SSH message IDs
     */
    MSG_UNKNOWN_ID_RESERVED_0({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(0.toByte()) } }),
    MSG_UNKNOWN_ID_TRANSPORT_GENERIC({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(9.toByte()) } }),
    MSG_UNKNOWN_ID_ALGORITHM_NEGOTIATION({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(22.toByte()) } }),
    MSG_UNKNOWN_ID_KEY_EXCHANGE_SPECIFIC({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(49.toByte()) } }),
    MSG_UNKNOWN_ID_USERAUTH_GENERIC({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(54.toByte()) } }),
    MSG_UNKNOWN_ID_USERAUTH_SPECIFIC({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(79.toByte()) } }),
    MSG_UNKNOWN_ID_CONNECTION_GENERIC({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(83.toByte()) } }),
    MSG_UNKNOWN_ID_CHANNEL_RELATED({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit(101.toByte()) } }),
    MSG_UNKNOWN_ID_RESERVED_CLIENT({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit((-128).toByte()) } }),
    MSG_UNKNOWN_ID_RESERVED_PRIVATE({ UnknownMessage() },
        { message, _ -> (message as UnknownMessage).apply { messageId = Modifiable.explicit((-64).toByte()) } });


    private fun createAndPrepare(context: SshContext): ProtocolMessage<*> = this.messageCreator().apply {
        getHandler(context).preparator.prepare()
    }

    fun createAndPrepareAndAfterPrepare(context: SshContext): ProtocolMessage<*> =
        createAndPrepare(context).apply { this@SshSymbol.afterPrepare?.invoke(this, context) }

}
