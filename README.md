# `vluks`: Hashicorp Vault LUKS

![Build status](https://ci.sapphic.systems/api/v1/teams/main/pipelines/vluks/jobs/nightly/badge)
![GitHub last commit](https://img.shields.io/github/last-commit/SapphicCode/vluks)

As the name might imply, `vluks` uses Hashicorp Vault in Transit mode to authorize decryption of LUKS version 2 disks.

It can be embedded into the first stage of the Linux boot process, to facilitate unlocking of LUKS volumes by providing keyfiles to `systemd-cryptsetup`. Keyfiles which are stored in the LUKS header itself, encrypted with Vault's transit secrets engine, enabling conditional access to volumes depending on the client's Vault privileges.

In future, `vluks` can also be run as a daemon on the resulting host, to shut down machines if it detects the Vault has become sealed or unreachable for an extended period of time.
