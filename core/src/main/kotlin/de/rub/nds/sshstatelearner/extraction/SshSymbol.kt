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
import de.rub.nds.sshattacker.core.protocol.authentication.message.*
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectStreamlocalOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectTcpIpMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedStreamlocalOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenUnknownMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenX11Message
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentReqOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEowOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitStatusMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyReqMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestShellMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11ReqMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelStreamlocalForwardOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestStreamlocalForwardOpenSshMessage
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
import de.rub.nds.sshattacker.core.protocol.transport.message.PingOpenSshMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.PongOpenSshMessage
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
    MSG_DEBUG({ DebugMessage() }),
    MSG_KEX_DH_GEX_GROUP({ DhGexKeyExchangeGroupMessage() }),
    MSG_KEX_DH_GEX_INIT({ DhGexKeyExchangeInitMessage() }),
    MSG_KEX_DH_GEX_OLD_REQUEST({ DhGexKeyExchangeOldRequestMessage() }),
    MSG_KEX_DH_GEX_REPLY({ DhGexKeyExchangeReplyMessage() }),
    MSG_KEX_DH_GEX_REQUEST({ DhGexKeyExchangeRequestMessage() }),
    MSG_KEXDH_INIT({ DhKeyExchangeInitMessage() }),
    MSG_KEXDH_REPLY({ DhKeyExchangeReplyMessage() }),
    MSG_DISCONNECT({ DisconnectMessage() }),
    MSG_KEX_ECDH_INIT({ EcdhKeyExchangeInitMessage() }),
    MSG_KEX_ECDH_REPLY({ EcdhKeyExchangeReplyMessage() }),
    MSG_EXT_INFO({ ExtensionInfoMessage() }),
    MSG_KEX_HBR_INIT({ HybridKeyExchangeInitMessage() }),
    MSG_KEX_HBR_REPLY({ HybridKeyExchangeReplyMessage() }),
    MSG_IGNORE({ IgnoreMessage() }),
    MSG_KEXINIT({ KeyExchangeInitMessage() }),
    MSG_NEWCOMPRESS({ NewCompressMessage() }),
    MSG_NEWKEYS({ NewKeysMessage() }),
    MSG_PING_OPENSSH({ PingOpenSshMessage() }),
    MSG_PONG_OPENSSH({ PongOpenSshMessage() }),
    MSG_KEX_RSA_DONE({ RsaKeyExchangeDoneMessage() }),
    MSG_KEX_RSA_PUBKEY({ RsaKeyExchangePubkeyMessage() }),
    MSG_KEX_RSA_SECRET({ RsaKeyExchangeSecretMessage() }),
    MSG_SERVICE_ACCEPT({ ServiceAcceptMessage() }),
    MSG_SERVICE_REQUEST_USERAUTH({
        ServiceRequestMessage().apply {
            setServiceName(Modifiable.explicit("ssh-userauth"), true)
        }
    }),
    MSG_SERVICE_REQUEST_CONNECTION({
        ServiceRequestMessage().apply {
            setServiceName(Modifiable.explicit("ssh-connection"), true)
        }
    }),
    MSG_UNIMPLEMENTED({
        UnimplementedMessage().apply {
            setSequenceNumber((it?.readSequenceNumber ?: 1) - 1)
        }
    }),
    MSG_VERSION_EXCHANGE({ VersionExchangeMessage() }),

    /*
     * SSH authentication protocol symbols
     */
    MSG_USERAUTH_BANNER({ UserAuthBannerMessage() }),
    MSG_USERAUTH_FAILURE({ UserAuthFailureMessage() }),
    MSG_USERAUTH_INFO_REQUEST({ UserAuthInfoRequestMessage() }),
    MSG_USERAUTH_INFO_RESPONSE({ UserAuthInfoResponseMessage() }),
    MSG_USERAUTH_PASSWD_CHANGEREQ({ UserAuthPasswdChangeReqMessage() }),
    MSG_USERAUTH_PK_OK({ UserAuthPkOkMessage() }),
    MSG_USERAUTH_REQUEST_HOSTBASED({ UserAuthRequestHostbasedMessage() }),
    MSG_USERAUTH_REQUEST_KEYBOARD_INTERACTIVE({ UserAuthRequestKeyboardInteractiveMessage() }),
    MSG_USERAUTH_REQUEST_NONE({ UserAuthRequestNoneMessage() }),
    MSG_USERAUTH_REQUEST_PASSWORD({ UserAuthRequestPasswordMessage().apply { setPassword(Modifiable.explicit("invalid"), true) } }),
    MSG_USERAUTH_REQUEST_PUBLICKEY_HOSTBOUND_OPENSSH({ UserAuthRequestPublicKeyHostboundOpenSshMessage() }),
    MSG_USERAUTH_REQUEST_PUBLICKEY({ UserAuthRequestPublicKeyMessage() }),
    MSG_USERAUTH_REQUEST_UNKNOWN({
        UserAuthRequestUnknownMessage().apply {
            setMethodName(Modifiable.explicit("unknown"), true)
    }}),
    MSG_USERAUTH_SUCCESS({ UserAuthSuccessMessage() }),

    /*
     * SSH connection protocol symbols
     */
    MSG_CHANNEL_CLOSE({ ChannelCloseMessage() }),
    MSG_CHANNEL_DATA({ ChannelDataMessage() }),
    MSG_CHANNEL_EOF({ ChannelEofMessage() }),
    MSG_CHANNEL_EXTENDED_DATA({ ChannelExtendedDataMessage() }),
    MSG_CHANNEL_FAILURE({ ChannelFailureMessage() }),
    MSG_CHANNEL_OPEN_CONFIRMATION({ ChannelOpenConfirmationMessage() }),
    MSG_CHANNEL_OPEN_DIRECT_STREAMLOCAL_OPENSSH({ ChannelOpenDirectStreamlocalOpenSshMessage() }),
    MSG_CHANNEL_OPEN_DIRECT_TCPIP({ ChannelOpenDirectTcpIpMessage() }),
    MSG_CHANNEL_OPEN_FAILURE({ ChannelOpenFailureMessage() }),
    MSG_CHANNEL_OPEN_FORWARDED_STREAMLOCAL_OPENSSH({ ChannelOpenForwardedStreamlocalOpenSshMessage() }),
    MSG_CHANNEL_OPEN_FORWARDED_TCPIP({ ChannelOpenForwardedTcpIpMessage() }),
    MSG_CHANNEL_OPEN_SESSION({ ChannelOpenSessionMessage() }),
    MSG_CHANNEL_OPEN_TUN_OPENSSH({ ChannelOpenTunOpenSshMessage() }),
    MSG_CHANNEL_OPEN_UNKNOWN({
        ChannelOpenUnknownMessage().apply {
            setChannelType(Modifiable.explicit("unknown"), true)
        }
    }),
    MSG_CHANNEL_OPEN_X11({ ChannelOpenX11Message() }),
    MSG_CHANNEL_REQUEST_AUTH_AGENT_OPENSSH({ ChannelRequestAuthAgentReqOpenSshMessage() }),
    MSG_CHANNEL_REQUEST_BREAK({ ChannelRequestBreakMessage() }),
    MSG_CHANNEL_REQUEST_ENV({ ChannelRequestEnvMessage() }),
    MSG_CHANNEL_REQUEST_EOW_OPENSSH({ ChannelRequestEowOpenSshMessage() }),
    MSG_CHANNEL_REQUEST_EXEC({ ChannelRequestExecMessage() }),
    MSG_CHANNEL_REQUEST_EXIT_SIGNAL({ ChannelRequestExitSignalMessage() }),
    MSG_CHANNEL_REQUEST_EXIT_STATUS({ ChannelRequestExitStatusMessage() }),
    MSG_CHANNEL_REQUEST_PTY_REQ({ ChannelRequestPtyReqMessage() }),
    MSG_CHANNEL_REQUEST_SHELL({ ChannelRequestShellMessage() }),
    MSG_CHANNEL_REQUEST_SIGNAL({ ChannelRequestSignalMessage() }),
    MSG_CHANNEL_REQUEST_SUBSYSTEM({ ChannelRequestSubsystemMessage() }),
    MSG_CHANNEL_REQUEST_UNKNOWN({
        ChannelRequestUnknownMessage().apply {
            setRequestType(Modifiable.explicit("unknown"), true)
        }
    }),
    MSG_CHANNEL_REQUEST_WINDOW_CHANGE({ ChannelRequestWindowChangeMessage() }),
    MSG_CHANNEL_REQUEST_X11_REQ({ ChannelRequestX11ReqMessage() }),
    MSG_CHANNEL_REQUEST_XON_XOFF({ ChannelRequestXonXoffMessage() }),
    MSG_CHANNEL_SUCCESS({ ChannelSuccessMessage() }),
    MSG_CHANNEL_WINDOW_ADJUST({ ChannelWindowAdjustMessage() }),
    MSG_GLOBAL_REQUEST_CANCEL_STREAMLOCAL_FORWARD_OPENSSH({ GlobalRequestCancelStreamlocalForwardOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD({ GlobalRequestCancelTcpIpForwardMessage() }),
    MSG_REQUEST_FAILURE({ GlobalRequestFailureMessage() }),
    MSG_GLOBAL_REQUEST_HOSTKEYS_OPENSSH({ GlobalRequestHostKeysOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_HOSTKEYS_PROVE_OPENSSH({ GlobalRequestHostKeysProveOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_NO_MORE_SESSIONS_OPENSSH({ GlobalRequestNoMoreSessionsOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_STREAMLOCAL_FORWARD_OPENSSH({ GlobalRequestStreamlocalForwardOpenSshMessage() }),
    MSG_REQUEST_SUCCESS({ GlobalRequestSuccessMessage() }),
    MSG_GLOBAL_REQUEST_TCPIP_FORWARD({ GlobalRequestTcpIpForwardMessage() }),
    MSG_GLOBAL_REQUEST_UNKNOWN({
        GlobalRequestUnknownMessage().apply {
            setRequestName(Modifiable.explicit("unknown"), true)
        }
    }),

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
