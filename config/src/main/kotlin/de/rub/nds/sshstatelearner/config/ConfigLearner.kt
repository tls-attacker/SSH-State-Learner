package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.constants.EquivalenceOracleType
import de.rub.nds.sshstatelearner.constants.LearningAlgorithmType

class ConfigLearner {
    @JsonPropertyDescription("The learning algorithm to use")
    @JsonProperty(defaultValue = "TTT")
    var learningAlgorithmType: LearningAlgorithmType = LearningAlgorithmType.TTT

    @JsonPropertyDescription(
        "If set, the state learner will not only output the final" +
                " hypothesis but rather every intermediate hypothesis"
    )
    @JsonProperty(defaultValue = "true")
    var outputIntermediateHypothesis: Boolean = true

    @JsonPropertyDescription("The equivalence oracle chain to use (comma-separated combination of CACHE_CONSISTENCY, HAPPY_FLOW, COMPLETE_EXPLORATION, RANDOM_WORDS, RANDOM_WALK, RANDOM_W, RANDOM_WP, W, WP)")
    @JsonProperty(defaultValue = "[CACHE_CONSISTENCY, HAPPY_FLOW, RANDOM_WORDS]")
    var equivOracleChainTypes: List<EquivalenceOracleType> = listOf(
        EquivalenceOracleType.CACHE_CONSISTENCY,
        EquivalenceOracleType.HAPPY_FLOW,
        EquivalenceOracleType.RANDOM_WORDS
    )


    @JsonPropertyDescription("[HAPPY_FLOW only] The length of the suffix to append to each possible happy flow prefix")
    @JsonProperty(defaultValue = "2")
    var equivHappyFlowSuffixLength = EquivalenceOracleFactory.happyFlowSuffixLength


    @JsonPropertyDescription("[COMPLETE_EXPLORATION only] The minimum depth to explore (i. e. the minimum length of words tested)")
    @JsonProperty(defaultValue = "3")
    var equivCompleteExplorationMinDepth = EquivalenceOracleFactory.completeExplorationMinDepth


    @JsonPropertyDescription("[COMPLETE_EXPLORATION only] The maximum depth to explore (i. e. the maximum length of words tested)")
    @JsonProperty(defaultValue = "6")
    var equivCompleteExplorationMaxDepth = EquivalenceOracleFactory.completeExplorationMaxDepth


    @JsonPropertyDescription("[RANDOM_WORDS only] Minimum length of random words used to test for equivalence of the hypothesis with the real SUL")
    @JsonProperty(defaultValue = "5")
    var equivRandomWordsMinLength: Int = EquivalenceOracleFactory.randomWordsMinLength


    @JsonPropertyDescription("[RANDOM_WORDS only] Maximum length of random words used to test for equivalence of the hypothesis with the real SUL")
    @JsonProperty(defaultValue = "15")
    var equivRandomWordsMaxLength: Int = EquivalenceOracleFactory.randomWordsMaxLength


    @JsonPropertyDescription("[RANDOM_WORDS only] Maximum number of random words to test before hypothesis and real SUL are considered equivalent")
    @JsonProperty(defaultValue = "1000")
    var equivRandomWordsMaxTests: Int = EquivalenceOracleFactory.randomWordsMaxTests


    @JsonPropertyDescription("[RANDOM_WALK only] The probability that the walk is restarted after a step")
    @JsonProperty(defaultValue = "0.1")
    var equivRandomWalkResetProbability: Double = EquivalenceOracleFactory.randomWalkRestartProbability


    @JsonPropertyDescription("[RANDOM_WALK only] Maximum number of steps to walk before hypothesis and SUL are considered equal")
    @JsonProperty(defaultValue = "10000")
    var equivRandomWalkMaxSteps: Long = EquivalenceOracleFactory.randomWalkMaxSteps


    @JsonPropertyDescription("[W / WP only] The maximum length of the \"middle\" part of all words generated")
    @JsonProperty(defaultValue = "10")
    var equivWMaxDepth: Int = EquivalenceOracleFactory.wMaxDepth


    @JsonPropertyDescription("[RANDOM_W / RANDOM_WP only] The minimal size of a random word")
    @JsonProperty(defaultValue = "3")
    var equivRandomWMinimalSize: Int = EquivalenceOracleFactory.randomWMinimalSize


    @JsonPropertyDescription("[RANDOM_W / RANDOM_WP only] The expected length of a random word. The effective expected length is minimal size + rnd length")
    @JsonProperty(defaultValue = "7")
    var equivRandomWRndLength: Int = EquivalenceOracleFactory.randomWRndLength


    @JsonPropertyDescription("[RANDOM_W / RANDOM_WP only] The maximum number of words to test before hypothesis and SUL are considered equal. If this oracle is configured to be unbounded (bound = 0), it does not terminate if the hypothesis is correct")
    @JsonProperty(defaultValue = "1000")
    var equivRandomWBound: Int = EquivalenceOracleFactory.randomWBound

}