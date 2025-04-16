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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant
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

enum class SshSymbol(val messageId: UByte?, val messageConstructor: (SshContext?) -> ProtocolMessage<*>) {

    /*
     * SSH transport protocol symbols
     */
    MSG_DEBUG(MessageIdConstant.SSH_MSG_DEBUG, { DebugMessage() }),
    MSG_KEX_DH_GEX_GROUP(MessageIdConstant.SSH_MSG_KEX_DH_GEX_GROUP, { DhGexKeyExchangeGroupMessage() }),
    MSG_KEX_DH_GEX_INIT(MessageIdConstant.SSH_MSG_KEX_DH_GEX_INIT, { DhGexKeyExchangeInitMessage() }),
    MSG_KEX_DH_GEX_OLD_REQUEST(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD, { DhGexKeyExchangeOldRequestMessage() }),
    MSG_KEX_DH_GEX_REPLY(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REPLY, { DhGexKeyExchangeReplyMessage() }),
    MSG_KEX_DH_GEX_REQUEST(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST, { DhGexKeyExchangeRequestMessage() }),
    MSG_KEXDH_INIT(MessageIdConstant.SSH_MSG_KEXDH_INIT, { DhKeyExchangeInitMessage() }),
    MSG_KEXDH_REPLY(MessageIdConstant.SSH_MSG_KEXDH_REPLY, { DhKeyExchangeReplyMessage() }),
    MSG_DISCONNECT(MessageIdConstant.SSH_MSG_DISCONNECT, { DisconnectMessage() }),
    MSG_KEX_ECDH_INIT(MessageIdConstant.SSH_MSG_KEX_ECDH_INIT, { EcdhKeyExchangeInitMessage() }),
    MSG_KEX_ECDH_REPLY(MessageIdConstant.SSH_MSG_KEX_ECDH_REPLY, { EcdhKeyExchangeReplyMessage() }),
    MSG_EXT_INFO(MessageIdConstant.SSH_MSG_EXT_INFO, { ExtensionInfoMessage() }),
    MSG_KEX_HBR_INIT(MessageIdConstant.SSH_MSG_HBR_INIT, { HybridKeyExchangeInitMessage() }),
    MSG_KEX_HBR_REPLY(MessageIdConstant.SSH_MSG_HBR_REPLY, { HybridKeyExchangeReplyMessage() }),
    MSG_IGNORE(MessageIdConstant.SSH_MSG_IGNORE, { IgnoreMessage() }),
    MSG_KEXINIT(MessageIdConstant.SSH_MSG_KEXINIT, { KeyExchangeInitMessage() }),
    MSG_NEWCOMPRESS(MessageIdConstant.SSH_MSG_NEWCOMPRESS, { NewCompressMessage() }),
    MSG_NEWKEYS(MessageIdConstant.SSH_MSG_NEWKEYS, { NewKeysMessage() }),
    MSG_PING_OPENSSH(MessageIdConstant.SSH_MSG_PING, { PingOpenSshMessage() }),
    MSG_PONG_OPENSSH(MessageIdConstant.SSH_MSG_PONG, { PongOpenSshMessage() }),
    MSG_KEX_RSA_DONE(MessageIdConstant.SSH_MSG_KEXRSA_DONE, { RsaKeyExchangeDoneMessage() }),
    MSG_KEX_RSA_PUBKEY(MessageIdConstant.SSH_MSG_KEXRSA_PUBKEY, { RsaKeyExchangePubkeyMessage() }),
    MSG_KEX_RSA_SECRET(MessageIdConstant.SSH_MSG_KEXRSA_SECRET, { RsaKeyExchangeSecretMessage() }),
    MSG_SERVICE_ACCEPT(MessageIdConstant.SSH_MSG_SERVICE_ACCEPT, { ServiceAcceptMessage() }),
    MSG_SERVICE_REQUEST_USERAUTH(MessageIdConstant.SSH_MSG_SERVICE_REQUEST, {
        ServiceRequestMessage().apply {
            setServiceName(Modifiable.explicit("ssh-userauth"), true)
        }
    }),
    MSG_SERVICE_REQUEST_CONNECTION(MessageIdConstant.SSH_MSG_SERVICE_REQUEST, {
        ServiceRequestMessage().apply {
            setServiceName(Modifiable.explicit("ssh-connection"), true)
        }
    }),
    MSG_UNIMPLEMENTED(MessageIdConstant.SSH_MSG_UNIMPLEMENTED, {
        UnimplementedMessage().apply {
            setSequenceNumber((it?.readSequenceNumber ?: 1) - 1)
        }
    }),
    MSG_VERSION_EXCHANGE(null, { VersionExchangeMessage() }),

    /*
     * SSH authentication protocol symbols
     */
    MSG_USERAUTH_BANNER(MessageIdConstant.SSH_MSG_USERAUTH_BANNER, { UserAuthBannerMessage() }),
    MSG_USERAUTH_FAILURE(MessageIdConstant.SSH_MSG_USERAUTH_FAILURE, { UserAuthFailureMessage() }),
    MSG_USERAUTH_INFO_REQUEST(MessageIdConstant.SSH_MSG_USERAUTH_INFO_REQUEST, { UserAuthInfoRequestMessage() }),
    MSG_USERAUTH_INFO_RESPONSE(MessageIdConstant.SSH_MSG_USERAUTH_INFO_RESPONSE, { UserAuthInfoResponseMessage() }),
    MSG_USERAUTH_PASSWD_CHANGEREQ(MessageIdConstant.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ, { UserAuthPasswdChangeReqMessage() }),
    MSG_USERAUTH_PK_OK(MessageIdConstant.SSH_MSG_USERAUTH_PK_OK, { UserAuthPkOkMessage() }),
    MSG_USERAUTH_REQUEST_HOSTBASED(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, { UserAuthRequestHostbasedMessage() }),
    MSG_USERAUTH_REQUEST_KEYBOARD_INTERACTIVE(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, { UserAuthRequestKeyboardInteractiveMessage() }),
    MSG_USERAUTH_REQUEST_NONE(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, { UserAuthRequestNoneMessage() }),
    MSG_USERAUTH_REQUEST_PASSWORD(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, { UserAuthRequestPasswordMessage().apply { setPassword(Modifiable.explicit("invalid"), true) } }),
    MSG_USERAUTH_REQUEST_PUBLICKEY_HOSTBOUND_OPENSSH(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, { UserAuthRequestPublicKeyHostboundOpenSshMessage() }),
    MSG_USERAUTH_REQUEST_PUBLICKEY(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, { UserAuthRequestPublicKeyMessage() }),
    MSG_USERAUTH_REQUEST_UNKNOWN(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST, {
        UserAuthRequestUnknownMessage().apply {
            setMethodName(Modifiable.explicit("unknown"), true)
    }}),
    MSG_USERAUTH_SUCCESS(MessageIdConstant.SSH_MSG_USERAUTH_SUCCESS, { UserAuthSuccessMessage() }),

    /*
     * SSH connection protocol symbols
     */
    MSG_CHANNEL_CLOSE(MessageIdConstant.SSH_MSG_CHANNEL_CLOSE, { ChannelCloseMessage() }),
    MSG_CHANNEL_DATA(MessageIdConstant.SSH_MSG_CHANNEL_DATA,{ ChannelDataMessage() }),
    MSG_CHANNEL_EOF(MessageIdConstant.SSH_MSG_CHANNEL_EOF, { ChannelEofMessage() }),
    MSG_CHANNEL_EXTENDED_DATA(MessageIdConstant.SSH_MSG_CHANNEL_EXTENDED_DATA, { ChannelExtendedDataMessage() }),
    MSG_CHANNEL_FAILURE(MessageIdConstant.SSH_MSG_CHANNEL_FAILURE, { ChannelFailureMessage() }),
    MSG_CHANNEL_OPEN_CONFIRMATION(MessageIdConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, { ChannelOpenConfirmationMessage() }),
    MSG_CHANNEL_OPEN_DIRECT_STREAMLOCAL_OPENSSH(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenDirectStreamlocalOpenSshMessage() }),
    MSG_CHANNEL_OPEN_DIRECT_TCPIP(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenDirectTcpIpMessage() }),
    MSG_CHANNEL_OPEN_FAILURE(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenFailureMessage() }),
    MSG_CHANNEL_OPEN_FORWARDED_STREAMLOCAL_OPENSSH(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenForwardedStreamlocalOpenSshMessage() }),
    MSG_CHANNEL_OPEN_FORWARDED_TCPIP(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenForwardedTcpIpMessage() }),
    MSG_CHANNEL_OPEN_SESSION(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenSessionMessage() }),
    MSG_CHANNEL_OPEN_TUN_OPENSSH(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenTunOpenSshMessage() }),
    MSG_CHANNEL_OPEN_UNKNOWN(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, {
        ChannelOpenUnknownMessage().apply {
            setChannelType(Modifiable.explicit("unknown"), true)
        }
    }),
    MSG_CHANNEL_OPEN_X11(MessageIdConstant.SSH_MSG_CHANNEL_OPEN, { ChannelOpenX11Message() }),
    MSG_CHANNEL_REQUEST_AUTH_AGENT_OPENSSH(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestAuthAgentReqOpenSshMessage() }),
    MSG_CHANNEL_REQUEST_BREAK(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestBreakMessage() }),
    MSG_CHANNEL_REQUEST_ENV(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestEnvMessage() }),
    MSG_CHANNEL_REQUEST_EOW_OPENSSH(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestEowOpenSshMessage() }),
    MSG_CHANNEL_REQUEST_EXEC(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestExecMessage() }),
    MSG_CHANNEL_REQUEST_EXIT_SIGNAL(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestExitSignalMessage() }),
    MSG_CHANNEL_REQUEST_EXIT_STATUS(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestExitStatusMessage() }),
    MSG_CHANNEL_REQUEST_PTY_REQ(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestPtyReqMessage() }),
    MSG_CHANNEL_REQUEST_SHELL(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestShellMessage() }),
    MSG_CHANNEL_REQUEST_SIGNAL(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestSignalMessage() }),
    MSG_CHANNEL_REQUEST_SUBSYSTEM(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestSubsystemMessage() }),
    MSG_CHANNEL_REQUEST_UNKNOWN(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, {
        ChannelRequestUnknownMessage().apply {
            setRequestType(Modifiable.explicit("unknown"), true)
        }
    }),
    MSG_CHANNEL_REQUEST_WINDOW_CHANGE(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestWindowChangeMessage() }),
    MSG_CHANNEL_REQUEST_X11_REQ(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestX11ReqMessage() }),
    MSG_CHANNEL_REQUEST_XON_XOFF(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST, { ChannelRequestXonXoffMessage() }),
    MSG_CHANNEL_SUCCESS(MessageIdConstant.SSH_MSG_CHANNEL_SUCCESS, { ChannelSuccessMessage() }),
    MSG_CHANNEL_WINDOW_ADJUST(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST, { ChannelWindowAdjustMessage() }),
    MSG_GLOBAL_REQUEST_CANCEL_STREAMLOCAL_FORWARD_OPENSSH(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestCancelStreamlocalForwardOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestCancelTcpIpForwardMessage() }),
    MSG_REQUEST_FAILURE(MessageIdConstant.SSH_MSG_REQUEST_FAILURE, { GlobalRequestFailureMessage() }),
    MSG_GLOBAL_REQUEST_HOSTKEYS_OPENSSH(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestHostKeysOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_HOSTKEYS_PROVE_OPENSSH(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestHostKeysProveOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_NO_MORE_SESSIONS_OPENSSH(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestNoMoreSessionsOpenSshMessage() }),
    MSG_GLOBAL_REQUEST_STREAMLOCAL_FORWARD_OPENSSH(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestStreamlocalForwardOpenSshMessage() }),
    MSG_REQUEST_SUCCESS(MessageIdConstant.SSH_MSG_REQUEST_SUCCESS, { GlobalRequestSuccessMessage() }),
    MSG_GLOBAL_REQUEST_TCPIP_FORWARD(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, { GlobalRequestTcpIpForwardMessage() }),
    MSG_GLOBAL_REQUEST_UNKNOWN(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST, {
        GlobalRequestUnknownMessage().apply {
            setRequestName(Modifiable.explicit("unknown"), true)
        }
    }),

    /*
     * Unknown SSH message IDs
     */
    MSG_UNKNOWN_ID_RESERVED_0(0.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(0.toByte()) } }),
    MSG_UNKNOWN_ID_TRANSPORT_GENERIC(9.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(9.toByte()) } }),
    MSG_UNKNOWN_ID_ALGORITHM_NEGOTIATION(22.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(22.toByte()) } }),
    MSG_UNKNOWN_ID_KEY_EXCHANGE_SPECIFIC(49.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(49.toByte()) } }),
    MSG_UNKNOWN_ID_USERAUTH_GENERIC(54.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(54.toByte()) } }),
    MSG_UNKNOWN_ID_USERAUTH_SPECIFIC(79.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(79.toByte()) } }),
    MSG_UNKNOWN_ID_CONNECTION_GENERIC(83.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(83.toByte()) } }),
    MSG_UNKNOWN_ID_CHANNEL_RELATED(101.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit(101.toByte()) } }),
    MSG_UNKNOWN_ID_RESERVED_CLIENT(128.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit((-128).toByte()) } }),
    MSG_UNKNOWN_ID_RESERVED_PRIVATE(192.toUByte(), { UnknownMessage().apply { messageId = Modifiable.explicit((-64).toByte()) } });

    constructor(messageId: MessageIdConstant, messageConstructor: (SshContext?) -> ProtocolMessage<*>) : this(messageId.id.toUByte(), messageConstructor)
}
