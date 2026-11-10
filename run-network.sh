# Runs the state learner against SSH servers reachable via network (NETWORK executor).
# The targets must already be running and listening, one server instance per port, e.g.
# via ./start_servers.sh (docker compose, Dropbear on 127.0.0.1:30020-30035).
#
# full testing with
# -p 30020-30035
# and
# --equiv-random-words-max-tests 10000

java -Xmx10g -XX:+HeapDumpOnOutOfMemoryError -jar core/apps/SSH-State-Learner.jar \
    -h localhost -p 30020 --name "Dropbear 2025.87" \
    --kex ECDH_SHA2_NISTP256 --stage TRANSPORT --strict-kex \
    --sul-type SERVER --equiv-random-words-max-tests 500 -o out \
    --executor NETWORK \
    --disable-rekex --auth-request-limit 1 \
    --alphabet MSG_KEXINIT,MSG_KEX_ECDH_INIT,MSG_NEWKEYS,MSG_SERVICE_REQUEST_USERAUTH
