https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates

https://go.microsoft.com/fwlink/?linkid=2097925

The TrustedTpm package ships these roots in its NationZ folder, but their subject is "NSING Technologies Pte. Ltd." and NSING has a TCG vendor ID of its own (NSG, id:4E534700), so they are kept apart from the Nations Technologies roots.

Only TPM 2.0 certs
