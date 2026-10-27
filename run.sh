# full testing with
# -p 30020-30035
# and
# --equiv-random-words-max-tests 10000 

java -Xmx10g -XX:+HeapDumpOnOutOfMemoryError -jar core/apps/SSH-State-Learner.jar \
    -p 30020-30023 --name "OpenSSH 9.6p1" \
    --kex ECDH_SHA2_NISTP256 --stage TRANSPORT --strict-kex \
    --sul-type SERVER --equiv-random-words-max-tests 500 -o out \
    --nyx-sharedir "$HOME/src/tls-attacker/nyx-targets/target/packed_targets/nyx_openssh_9.6p1" \
    --executor NYX \
    --disable-rekex --auth-request-limit 1 # \
    # --alphabet MSG_KEXINIT,MSG_KEX_ECDH_INIT,MSG_NEWKEYS,MSG_SERVICE_REQUEST_USERAUTH
