# Qualcomm Recovery crypto common layer

This directory contains the parts shared by Qualcomm Android 17 Recovery
profiles. It is installed as `device/qcom/recovery-crypto-common` and is
referenced by a device profile; it is not enabled by itself.

Shared files include the Gatekeeper/SharedSecret compatibility bridge, QCOM
device-node permissions, and the base Recovery SELinux labels. A device still
owns its actual KeyMint/Gatekeeper libraries, firmware paths, fstab, service
names, VINTF instances, and vendor dependency manifest.

The common layer is deliberately opt-in. A device which does not inherit its
profile keeps the normal Recovery build and does not start any crypto service.
