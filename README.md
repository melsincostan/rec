# REC: Row EnCryption

**This is not meant to be relied on for proper security. It is an experimental toy to test encrypting data row by row. It is likely to have subtle weaknesses and vulnerabilities. Do not rely on this in production**

The goal of this module is to provide a primitive type that can be stored in a database that allows to encrypt rows independently.
This package only provides the type and no database interaction.
The goal is to try to provide functions for encryption, decryption, and support multiple version / algorithms, allowing rotation of keys or algorithm in a somewhat simple way.

This is meant to be a learning experience, feedback is welcome.

Again, this attempts to be secure but is bound to have flaws that make it not so.
