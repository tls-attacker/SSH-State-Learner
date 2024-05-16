package de.rub.nds.sshstatelearner.analysis.limiter.message

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler
import de.rub.nds.sshattacker.core.state.SshContext

class NotInStateMachineLearningFocusMessage : ProtocolMessage<NotInStateMachineLearningFocusMessage>() {
    override fun getHandler(context: SshContext?): ProtocolMessageHandler<NotInStateMachineLearningFocusMessage> {
        throw IllegalStateException("This message typ should only be used to limit the state machine learning.")
    }

    override fun toCompactString() = "NotInStateMachineLearningFocusMessage"
}