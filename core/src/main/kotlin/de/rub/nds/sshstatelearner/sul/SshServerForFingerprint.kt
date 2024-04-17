package de.rub.nds.sshstatelearner.sul

import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.connection.InboundConnection
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType
import de.rub.nds.sshstatelearner.util.SshConfigManager

class SshServerForFingerprint(port: Int) {
    private val config: Config =
        SshConfigManager.getServerConfig().apply {
            workflowTraceType = WorkflowTraceType.FULL
            defaultServerConnection = InboundConnection(port)
        }

    private val state: State = State(config)

    private val workflowExecuter = DefaultWorkflowExecutor(state)

    fun execute() {
        workflowExecuter.executeWorkflow()
    }

    fun close() {
        if (!state.sshContext.transportHandler.isInitialized) {
            state.sshContext.transportHandler.closeConnection()
        }
    }

}