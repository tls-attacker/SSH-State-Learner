package de.rub.nds.sshstatelearner.sul.symbols

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import net.automatalib.words.Word

object HappyFlowFactory {
    private fun constructKexFlow(kex: KeyExchangeAlgorithm): Array<SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                DhGexKeyExchangeRequestMessage().toSymbol(),
                DhGexKeyExchangeInitMessage().toSymbol()
            )
            KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                DhKeyExchangeInitMessage().toSymbol()
            )
            KeyExchangeFlowType.ECDH -> arrayOf(
                EcdhKeyExchangeInitMessage().toSymbol()
            )
            else -> TODO("Key exchange algorithm flow type ${kex.flowType} is not yet supported by SSH-Attacker")
        }
    }

    fun constructHappyFlow(stage: ProtocolStage, kex: KeyExchangeAlgorithm): Word<SshSymbol> {
        return when (stage) {
            ProtocolStage.TRANSPORT -> Word.fromSymbols(
                VersionExchangeMessage().toSymbol(),
                KeyExchangeInitMessage().toSymbol(),
                *constructKexFlow(kex),
                NewKeysMessage().toSymbol(),
                ServiceRequestMessage().toSymbol()
            )
            ProtocolStage.AUTHENTICATION -> Word.fromSymbols(
                UserAuthPasswordMessage().toSymbol()
            )
            ProtocolStage.CONNECTION -> Word.fromSymbols(
                ChannelOpenMessage().toSymbol(),
                ChannelRequestExecMessage().toSymbol()
            )
        }
    }
}