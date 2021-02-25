FROM gitpod/workspace-full

RUN sudo apt-get update && \
    sudo apt-get install -y cryptsetup-bin

# Hashicorp repository:
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add - && \
    sudo apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.releases.hashicorp.com $(lsb_release -cs) main" && \
    sudo apt-get update && \
    sudo apt-get install vault
