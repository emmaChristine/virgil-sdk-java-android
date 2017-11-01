# Loading Key

This guide shows how to load a private **Virgil Key**, which is stored on the device. The key must be loaded when Alice wants to **sign** some data, **decrypt** any encrypted content, and perform cryptographic operations.

Before loading a Virgil Key, set up your project environment with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To load the Virgil Key from the default storage:

- Initialize the **Virgil SDK**

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

- Alice has to load her Virgil Key from the protected storage and enter the Virgil Key password:

```java
// load a Virgil Key from storage
VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]",
    "[OPTIONAL_KEY_PASSWORD]");
```

To load a Virgil Key from a specific storage, developers need to change the storage path during Virgil SDK initialization.
