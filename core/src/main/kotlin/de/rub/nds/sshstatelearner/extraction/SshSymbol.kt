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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthKeyboardInteractiveMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitStatusMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestShellMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestTcpIpForwardMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage
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

enum class SshSymbol(val messageConstructor: (SshContext?) -> ProtocolMessage<*>) {
    /*
     * SSH transport protocol symbols
     */
    MSG_VERSION_EXCHANGE({ VersionExchangeMessage() }),
    MSG_DISCONNECT({ DisconnectMessage() }),
    MSG_IGNORE({ IgnoreMessage() }),
    MSG_UNIMPLEMENTED({
        UnimplementedMessage().apply {
            setSequenceNumber((it?.readSequenceNumber ?: 1) - 1)
        }
    }),
    MSG_DEBUG({ DebugMessage() }),
    MSG_SERVICE_REQUEST_USERAUTH({
        ServiceRequestMessage().apply {
            setServiceName(Modifiable.explicit("ssh-userauth"), true)
        }
    }),
    MSG_SERVICE_ACCEPT({ ServiceAcceptMessage() }),
    MSG_EXT_INFO({ ExtensionInfoMessage() }),
    MSG_NEWCOMPRESS({ NewCompressMessage() }),
    MSG_KEXINIT({ KeyExchangeInitMessage() }),
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
    MSG_USERAUTH_REQUEST_PUBLICKEY({ UserAuthPubkeyMessage() }),
    MSG_USERAUTH_REQUEST_HOSTBASED({ UserAuthHostbasedMessage() }),
    MSG_USERAUTH_REQUEST_KEYBOARD_INTERACTIVE({ UserAuthKeyboardInteractiveMessage() }),
    MSG_USERAUTH_REQUEST_PASSWD({ UserAuthPasswordMessage() }),
    MSG_USERAUTH_REQUEST_NONE({ UserAuthNoneMessage() }),
    MSG_USERAUTH_SUCCESS({ UserAuthSuccessMessage() }),
    MSG_USERAUTH_FAILURE({ UserAuthFailureMessage() }),
    MSG_USERAUTH_BANNER({ UserAuthBannerMessage() }),
    MSG_USERAUTH_INFO_REQUEST({ UserAuthInfoRequestMessage() }),
    MSG_USERAUTH_INFO_RESPONSE({ UserAuthInfoResponseMessage() }),
    MSG_SERVICE_REQUEST_CONNECTION({
        ServiceRequestMessage().apply {
            setServiceName(Modifiable.explicit("ssh-connection"), true)
        }
    }),

    /*
     * SSH connection protocol symbols
     */
    MSG_GLOBAL_REQUEST_NO_MORE_SESSIONS({ GlobalRequestNoMoreSessionsMessage() }),
    MSG_GLOBAL_REQUEST_TCPIP_FORWARD({ GlobalRequestTcpIpForwardMessage() }),
    MSG_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD({ GlobalRequestCancelTcpIpForwardMessage() }),
    MSG_GLOBAL_REQUEST_OPENSSH_HOSTKEYS({ GlobalRequestOpenSshHostKeysMessage() }),
    //MSG_GLOBAL_REQUEST_STREAMLOCAL_FORWARD
    //MSG_GLOBAL_REQUEST_CANCEL_STREAMLOCAL_FORWARD
    //MSG_GLOBAL_REQUEST_HOSTKEYS_PROVE_00_OPENSSH_COM
    MSG_GLOBAL_REQUEST_UNKNOWN({
        GlobalRequestUnknownMessage().apply {
            setRequestName(Modifiable.explicit("unknown"), true)
        }
    }),
    MSG_REQUEST_SUCCESS({ GlobalRequestSuccessMessage() }),
    MSG_REQUEST_FAILURE({ GlobalRequestFailureMessage() }),
    MSG_CHANNEL_OPEN_SESSION({ ChannelOpenSessionMessage() }),
    MSG_CHANNEL_OPEN_CONFIRMATION({ ChannelOpenConfirmationMessage() }),
    MSG_CHANNEL_OPEN_FAILURE({ ChannelOpenFailureMessage() }),
    MSG_CHANNEL_WINDOW_ADJUST({ ChannelWindowAdjustMessage() }),
    MSG_CHANNEL_DATA({ ChannelDataMessage() }),
    MSG_CHANNEL_EXTENDED_DATA({ ChannelExtendedDataMessage() }),
    MSG_CHANNEL_EOF({ ChannelEofMessage() }),
    MSG_CHANNEL_CLOSE({ ChannelCloseMessage() }),
    MSG_CHANNEL_REQUEST_PTY({ ChannelRequestPtyMessage() }),
    MSG_CHANNEL_REQUEST_X11({ ChannelRequestX11Message() }),
    MSG_CHANNEL_REQUEST_ENV({ ChannelRequestEnvMessage() }),
    MSG_CHANNEL_REQUEST_SHELL({ ChannelRequestShellMessage() }),
    MSG_CHANNEL_REQUEST_EXEC({ ChannelRequestExecMessage() }),
    MSG_CHANNEL_REQUEST_SUBSYSTEM({ ChannelRequestSubsystemMessage() }),
    MSG_CHANNEL_REQUEST_WINDOW_CHANGE({ ChannelRequestWindowChangeMessage() }),
    MSG_CHANNEL_REQUEST_XON_XOFF({ ChannelRequestXonXoffMessage() }),
    MSG_CHANNEL_REQUEST_SIGNAL({ ChannelRequestSignalMessage() }),
    MSG_CHANNEL_REQUEST_EXIT_STATUS({ ChannelRequestExitStatusMessage() }),
    MSG_CHANNEL_REQUEST_EXIT_SIGNAL({ ChannelRequestExitSignalMessage() }),
    MSG_CHANNEL_REQUEST_BREAK({ ChannelRequestBreakMessage() }),
    MSG_CHANNEL_REQUEST_AUTH_AGENT({ ChannelRequestAuthAgentMessage() }),
    // MSG_CHANNEL_REQUEST_EOW
    MSG_CHANNEL_REQUEST_UNKNOWN({
        ChannelRequestUnknownMessage().apply {
            setRequestType(Modifiable.explicit("unknown"), true)
        }
    }),
    MSG_CHANNEL_SUCCESS({ ChannelSuccessMessage() }),
    MSG_CHANNEL_FAILURE({ ChannelFailureMessage() }),

    /*
     * Unknown SSH message IDs
     */
    MSG_UNKNOWN_ID_RESERVED_0({ UnknownMessage().apply { messageId = Modifiable.explicit(0.toByte()) } }),
    MSG_UNKNOWN_ID_TRANSPORT_GENERIC({ UnknownMessage().apply { messageId = Modifiable.explicit(9.toByte()) } }),
    MSG_UNKNOWN_ID_ALGORITHM_NEGOTIATION({ UnknownMessage().apply { messageId = Modifiable.explicit(22.toByte()) } }),
    MSG_UNKNOWN_ID_KEY_EXCHANGE_SPECIFIC({ UnknownMessage().apply { messageId = Modifiable.explicit(49.toByte()) } }),
    MSG_UNKNOWN_ID_USERAUTH_GENERIC({ UnknownMessage().apply { messageId = Modifiable.explicit(54.toByte()) } }),
    MSG_UNKNOWN_ID_USERAUTH_SPECIFIC({ UnknownMessage().apply { messageId = Modifiable.explicit(79.toByte()) } }),
    MSG_UNKNOWN_ID_CONNECTION_GENERIC({ UnknownMessage().apply { messageId = Modifiable.explicit(83.toByte()) } }),
    MSG_UNKNOWN_ID_CHANNEL_RELATED({ UnknownMessage().apply { messageId = Modifiable.explicit(101.toByte()) } }),
    MSG_UNKNOWN_ID_RESERVED_CLIENT({ UnknownMessage().apply { messageId = Modifiable.explicit((-128).toByte()) } }),
    MSG_UNKNOWN_ID_RESERVED_PRIVATE({ UnknownMessage().apply { messageId = Modifiable.explicit((-64).toByte()) } });
}
