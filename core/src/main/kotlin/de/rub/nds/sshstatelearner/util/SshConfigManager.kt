package de.rub.nds.sshstatelearner.util

import de.rub.nds.modifiablevariable.util.ArrayConverter
import de.rub.nds.sshattacker.core.config.Config
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

object SshConfigManager {

    private fun getSshPublicKey(): SshPublicKey<CustomEcPublicKey, CustomEcPrivateKey> = SshPublicKey(
        PublicKeyFormat.ECDSA_SHA2_NISTP521,
        CustomEcPublicKey(
            PointFormatter.formatFromByteArray(
                NamedEcGroup.SECP521R1,
                ArrayConverter.hexStringToByteArray(
                    "04007a9a61317b93ec991102aea304" +
                            "7641b3b91254d5267ac1bade8972db" +
                            "7ee61dd0189d5663ff1988815e2632" +
                            "7634465f38f12112db2caa87020528" +
                            "e40091140810da01c643704d3bad15" +
                            "88572e1eeb36080c25e307e99f5263" +
                            "6c926c5c15eccaf5526ff2c79e3e5f" +
                            "683be0bfa5bd806217b690fd6bbfcc" +
                            "ca27cd82fd79bb194fccae7858"
                )
            ),
            NamedEcGroup.SECP521R1
        ),
        CustomEcPrivateKey(
            BigInteger(
                "01cac52efb225c5321f43e80bd28ee" +
                        "e0c9f21297684305586bcc68dded8d" +
                        "dc2acb2554b015810c8913211a8238" +
                        "a0cb56aa9c2295143e62afa476b4a4" +
                        "4fad5fee4717",
                16
            ),
            NamedEcGroup.SECP521R1
        )
    )

    private fun getDefaultConfig(): Config = Config.createConfig().apply {
        workflowTraceType = WorkflowTraceType.KEX_INIT_ONLY
        stopActionsAfterDisconnect = false
        stopActionsAfterIOException = false
        serviceName = "ssh-userauth"
        clientSupportedEncryptionAlgorithmsClientToServer = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
        clientSupportedEncryptionAlgorithmsServerToClient = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
    }

    /**
     * Creates a Config for Server.
     */
    fun getServerConfig(kex: KeyExchangeAlgorithm = SshSul.DEFAULT_KEX_ALGORITHM): Config =
        getDefaultConfig().apply {
            serverSupportedKeyExchangeAlgorithms = listOf(kex)
            defaultRunningMode = RunningModeType.SERVER
            serverSupportedHostKeyAlgorithms = listOf(PublicKeyAlgorithm.ECDSA_SHA2_NISTP521)
            clientSupportedHostKeyAlgorithms = listOf(PublicKeyAlgorithm.ECDSA_SHA2_NISTP521)
            hostKeys = listOf(
                getSshPublicKey()
            )
        }

    /**
     * Creates a Config for Client.
     */
    fun getClientConfig(kex: KeyExchangeAlgorithm = SshSul.DEFAULT_KEX_ALGORITHM): Config =
        getDefaultConfig().apply {
            clientSupportedKeyExchangeAlgorithms = listOf(kex)
            userKeys = listOf(
                getSshPublicKey()
            )
        }
}