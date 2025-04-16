/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.visualization

import de.rub.nds.sshstatelearner.analysis.data.GraphDetails
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.automaton.graph.TransitionEdge
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.automaton.visualization.AutomatonVisualizationHelper
import net.automatalib.visualization.VisualizationHelper
import net.automatalib.alphabet.Alphabet

class ShortMealyVisualizationHelper<S, T>(
    automaton: MealyMachine<S, SshSymbol, T, ResponseFingerprint>,
    private val alphabet: Alphabet<SshSymbol>,
    private val graphDetails: GraphDetails<S, SshSymbol, T>,
    private val detail: VisualizationDetail
) : AutomatonVisualizationHelper<S, SshSymbol, T, MealyMachine<S, SshSymbol, T, ResponseFingerprint>>(automaton) {

    private val combinedEdges: MutableSet<Pair<S, S>> = mutableSetOf()

    constructor(
        automaton: MealyMachine<S, SshSymbol, T, ResponseFingerprint>,
        alphabet: Alphabet<SshSymbol>,
        graphDetails: GraphDetails<S, SshSymbol, T>
    ) : this(automaton, alphabet, graphDetails, VisualizationDetail.LONG)

    override fun getEdgeProperties(
        src: S,
        edge: TransitionEdge<SshSymbol, T>,
        tgt: S,
        properties: MutableMap<String, String>
    ): Boolean {
        // Do not output an edge if super advices us to
        if (!super.getEdgeProperties(src, edge, tgt, properties)) {
            return false
        }

        // Output happy flow edges as a bold green edge
        if (graphDetails.happyFlowTransitions.contains(edge.transition)) {
            properties[VisualizationHelper.EdgeAttrs.COLOR] = "GREEN"
            properties[VisualizationHelper.EdgeAttrs.STYLE] = "bold"
        }

        return when (detail) {
            VisualizationDetail.SHORT -> getEdgePropertiesShort(src, edge, tgt, properties)
            VisualizationDetail.MEDIUM -> getEdgePropertiesMedium(src, edge, tgt, properties)
            VisualizationDetail.LONG -> getEdgePropertiesLong(src, edge, tgt, properties)
        }
    }

    private fun getEdgePropertiesShort(src: S, edge: TransitionEdge<SshSymbol, T>, tgt: S, properties: MutableMap<String, String>): Boolean {
        val transitionOutput = automaton.getTransitionOutput(edge.transition)
        // Do not output a circular edge if no output is generated
        if (src === tgt && transitionOutput.messages.isEmpty()) {
            return false
        }
        // Do not output this edge if a combined edge was already outputted
        // Exception: Happy flow transitions are excluded from edge combination
        if (combinedEdges.contains(src to tgt) && !graphDetails.happyFlowTransitions.contains(edge.transition)) {
            return false
        }

        if (!graphDetails.happyFlowTransitions.contains(edge.transition)) {
            // Combine multiple edges between src and tgt into a single one
            val label = alphabet.map { Triple(it, automaton.getTransition(src, it), automaton.getSuccessor(src, it)) }
                .filter { it.third === tgt && !graphDetails.happyFlowTransitions.contains(it.second) }
                .joinToString("\n") {
                    val output = automaton.getTransitionOutput(it.second)
                    return@joinToString if (output.messages.isEmpty()) {
                        "${it.first}"
                    } else {
                        "${it.first} / ${output.messages.joinToString(",") {
                                message ->
                            message.toCompactString()
                        }}"
                    }
                }
            properties[VisualizationHelper.EdgeAttrs.LABEL] = label
            combinedEdges.add(src to tgt)
        } else {
            val output = automaton.getTransitionOutput(edge.transition)
            if (output.messages.isEmpty()) {
                properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input}"
            } else if (output.decryptionFailure) {
                properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / {{DecryptionFailure}}"
            } else {
                properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / ${output.messages.joinToString(",") { it.toCompactString() }}"
            }
        }

        return true
    }

    private fun getEdgePropertiesMedium(src: S, edge: TransitionEdge<SshSymbol, T>, tgt: S, properties: MutableMap<String, String>): Boolean {
        val transitionOutput = automaton.getTransitionOutput(edge.transition)
        // Do not output this edge if a combined edge was already outputted
        // Exception: Happy flow transitions are excluded from edge combination
        if (combinedEdges.contains(src to tgt) && !graphDetails.happyFlowTransitions.contains(edge.transition)) {
            return false
        }

        if (!graphDetails.happyFlowTransitions.contains(edge.transition)) {
            // Combine multiple edges between src and tgt into a single one
            val label = alphabet.map { Triple(it, automaton.getTransition(src, it), automaton.getSuccessor(src, it)) }
                .filter { it.third === tgt && !graphDetails.happyFlowTransitions.contains(it.second) }
                .joinToString("\n") {
                    val output = automaton.getTransitionOutput(it.second)
                    return@joinToString if (output.messages.isEmpty()) {
                        "${it.first}"
                    } else if (output.decryptionFailure) {
                        "${it.first} / {{DecryptionFailure}}"
                    } else {
                        "${it.first} / ${output.messages.joinToString(",") {
                                message ->
                            message.toCompactString()
                        }}"
                    }
                }
            properties[VisualizationHelper.EdgeAttrs.LABEL] = label
            combinedEdges.add(src to tgt)
        } else {
            val output = automaton.getTransitionOutput(edge.transition)
            if (output.messages.isEmpty()) {
                properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / [No output]"
            } else if (output.decryptionFailure) {
                properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / {{DecryptionFailure}}"
            } else {
                properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / ${output.messages.joinToString(",") { it.toCompactString() }}"
            }
        }

        return true
    }

    private fun getEdgePropertiesLong(src: S, edge: TransitionEdge<SshSymbol, T>, tgt: S, properties: MutableMap<String, String>): Boolean {
        val transitionOutput = automaton.getTransitionOutput(edge.transition)
        // Compose edge label for long visualization
        if (transitionOutput.messages.isEmpty()) {
            properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / [No output]"
        } else if (transitionOutput.decryptionFailure) {
            properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / {{DecryptionFailure}}"
        } else {
            properties[VisualizationHelper.EdgeAttrs.LABEL] = "${edge.input} / ${
            transitionOutput.messages.joinToString(",") { it.toCompactString() }
            }"
        }

        return true
    }

    override fun getNodeProperties(node: S, properties: MutableMap<String, String>): Boolean {
        // Do not output a node if super advices us to
        if (!super.getNodeProperties(node, properties)) {
            return false
        }

        val stateNames = graphDetails.extractStateNames()
        val nodeLabelBuilder = StringBuilder()
        if (stateNames.contains(node)) {
            when (detail) {
                VisualizationDetail.LONG ->
                    nodeLabelBuilder.append("${stateNames[node]}\n($node")
                VisualizationDetail.MEDIUM, VisualizationDetail.SHORT ->
                    nodeLabelBuilder.append("${stateNames[node]}")
            }
        } else {
            nodeLabelBuilder.append("Unknown State ($node)")
        }
        if (graphDetails.socketStateMap.contains(node)) {
            nodeLabelBuilder.append("\n\nSocketState: ${graphDetails.socketStateMap[node]}")
        }
        properties[VisualizationHelper.NodeAttrs.LABEL] = nodeLabelBuilder.toString()

        properties[VisualizationHelper.NodeAttrs.FIXEDSIZE] = "true"
        properties[VisualizationHelper.NodeAttrs.WIDTH] = "2.3"
        properties[VisualizationHelper.NodeAttrs.HEIGHT] = "2.3"

        if (node === graphDetails.errorState) {
            properties[VisualizationHelper.NodeAttrs.COLOR] = "RED"
        }

        if (detail == VisualizationDetail.SHORT && node === graphDetails.notInStateMachineLearningFocusState) {
            return false
        }
        return true
    }
}
