/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.api.oracle.EquivalenceOracle
import de.learnlib.api.oracle.MembershipOracle
import de.learnlib.api.query.DefaultQuery
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.sshstatelearner.sul.symbols.toSymbol
import de.rub.nds.sshstatelearner.util.combinations
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Word

class HappyFlowEQOracle(private val membershipOracle: MembershipOracle<SshSymbol, Word<ResponseFingerprint>>, private val stage: ProtocolStage, private val suffixLength: Int) : EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {

    companion object {
        val HAPPY_FLOWS: Map<ProtocolStage, Word<SshSymbol>> = mapOf(
            ProtocolStage.TRANSPORT to Word.fromSymbols(
                VersionExchangeMessage().toSymbol(),
                KeyExchangeInitMessage().toSymbol(),
                DhGexKeyExchangeRequestMessage().toSymbol(),
                DhGexKeyExchangeInitMessage().toSymbol(),
                NewKeysMessage().toSymbol(),
                ServiceRequestMessage().toSymbol()
            ),
            // TODO: Define happy flows for ProtocolStage.AUTHENTICATION and ProtocolStage.CONNECTION
            ProtocolStage.AUTHENTICATION to Word.epsilon(),
            ProtocolStage.CONNECTION to Word.epsilon()
        )
    }

    override fun findCounterExample(
        hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>,
        alphabet: MutableCollection<out SshSymbol>
    ): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
        val happyFlowPrefixes = HAPPY_FLOWS[stage]!!.prefixes(true)
        for (prefix in happyFlowPrefixes) {
            val suffixes = alphabet.combinations(suffixLength).map { Word.fromList(it) }
            for (suffix in suffixes) {
                val input = Word.fromWords(prefix, suffix)
                val sulOutput = membershipOracle.answerQuery(input)
                val hypothesisOutput = hypothesis.computeOutput(input)
                sulOutput.zip(hypothesisOutput).forEach {
                    if (it.first != it.second) {
                        return DefaultQuery(input, sulOutput)
                    }
                }
            }
        }
        return null
    }
}
