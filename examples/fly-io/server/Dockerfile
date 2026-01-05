FROM scratch

COPY bin/gimlet-server /gimlet-server
COPY keys/ /keys/

ENV GIMLET_SERVER_TOKEN_PUBLIC_KEY_DIR=/keys

ENTRYPOINT ["/gimlet-server"]
