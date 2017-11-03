# Exporting Virgil Key

This guide shows how to export a **Virgil Key** to the string representation.

Set up your project environment before you begin to export a Virgil Key, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To export the Virgil Key:

- Initialize **Virgil SDK**

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

- Alice Generates a Virgil Key
- After Virgil Key generated, developers can export Alice's Virgil Key to a Base64 encoded string

```java
// generate a new Virgil Key
VirgilKey aliceKey = virgil.getKeys().generate();

// export the Virgil Key
String exportedAliceKey = aliceKey.export("[OPTIONAL_KEY_PASSWORD]")
    .toString(StringEncoding.Base64);
```

Developers also can extract a Public Key from a Private Key using the Virgil CLI.
