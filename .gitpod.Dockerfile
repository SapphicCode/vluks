FROM gitpod/workspace-full

RUN sudo apt-get update && \
    sudo apt-get install -y cryptsetup-bin

# TODO: Hashicorp Vault repository
