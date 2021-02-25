FROM gitpod/workspace-full

RUN sudo apt-get update && \
    sudo apt-get install cryptsetup

# TODO: Hashicorp Vault repository
