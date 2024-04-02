package de.rub.nds.sshstatelearner.constants

enum class SULTyp(val isClientAlphabet: Boolean) {
    SERVER_IS_UNDER_TEST(true),
    CLIENT_IS_UNDER_TEST(false),
    CLIENT_IS_UNDER_TEST2(false),
}