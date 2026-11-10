# Runs the state learner against an SSH server inside a Nyx VM (NYX executor).
# The target must be provided as a packed Nyx target (sharedir, see --nyx-sharedir);
# the learner starts the VM itself, no running server is required.
# Only a single SUL instance is used, -p has no effect with the NYX executor.

java -Xmx10g -XX:+HeapDumpOnOutOfMemoryError -jar core/apps/SSH-State-Learner.jar \
    -p 30020-30023 --name "OpenSSH 9.6p1" \
    --kex ECDH_SHA2_NISTP256 --stage TRANSPORT --strict-kex \
    --sul-type SERVER --equiv-random-words-max-tests 500 -o out \
    --nyx-sharedir "$HOME/src/tls-attacker/nyx-targets/target/packed_targets/nyx_openssh_9.9p2/" \
    --executor NYX \
    --disable-rekex --auth-request-limit 1 \
    --alphabet MSG_KEXINIT,MSG_KEX_ECDH_INIT,MSG_NEWKEYS,MSG_SERVICE_REQUEST_USERAUTH
