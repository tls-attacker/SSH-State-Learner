package de.rub.nds.sshstatelearner.util

import de.rub.nds.modifiablevariable.util.ArrayConverter
import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.constants.CompressionMethod
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.NamedEcGroup
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat
import de.rub.nds.sshattacker.core.constants.RunningModeType
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType
import de.rub.nds.sshstatelearner.sul.SshSul
import java.math.BigInteger

/**
 * Object that returns a default SSH configuration.
 */
object SshConfigManager {

    private fun getDefaultConfig(): Config = Config().apply {
        workflowTraceType = WorkflowTraceType.KEX_INIT_ONLY
        stopActionsAfterDisconnect = false
        stopActionsAfterIOException = false
        fallbackToNoneCipherOnDecryptionException = false
        serviceName = "ssh-userauth"
    }

    /**
     * Creates a Config for Server.
     */
    fun getServerConfig(
        kex: KeyExchangeAlgorithm = SshSul.DEFAULT_KEX_ALGORITHM,
        strictKex: Boolean = SshSul.DEFAULT_STRICT_KEX_ENABLED
    ): Config =
        getDefaultConfig().apply {
            serverSupportedKeyExchangeAlgorithms = if (strictKex) {
                listOf(kex, KeyExchangeAlgorithm.KEX_STRICT_S_V00_OPENSSH_COM)
            } else {
                listOf(kex)
            }
            defaultRunningMode = RunningModeType.SERVER
            serverSupportedHostKeyAlgorithms = listOf(PublicKeyAlgorithm.ECDSA_SHA2_NISTP521)
            serverSupportedCompressionMethodsClientToServer = listOf(CompressionMethod.NONE)
            serverSupportedCompressionMethodsServerToClient = listOf(CompressionMethod.NONE)
        }

    /**
     * Creates a Config for Client.
     */
    fun getClientConfig(
        kex: KeyExchangeAlgorithm = SshSul.DEFAULT_KEX_ALGORITHM,
        strictKex: Boolean = SshSul.DEFAULT_STRICT_KEX_ENABLED
    ): Config =
        getDefaultConfig().apply {
            clientSupportedKeyExchangeAlgorithms = if (strictKex) {
                listOf(kex, KeyExchangeAlgorithm.KEX_STRICT_C_V00_OPENSSH_COM)
            } else {
                listOf(kex)
            }
            defaultRunningMode = RunningModeType.CLIENT
            clientSupportedCompressionMethodsClientToServer = listOf(CompressionMethod.NONE)
            clientSupportedCompressionMethodsServerToClient = listOf(CompressionMethod.NONE)
        }
}