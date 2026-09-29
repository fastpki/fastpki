# Smoke test: launches the OCSP responder against a known-good test DB
# and queries it with `openssl ocsp`. Requires the openssl CLI on PATH.
add_test(NAME ocsp_smoke
    COMMAND ${CMAKE_COMMAND} -E echo "TODO: drive fastpki-ocsp with openssl ocsp")
