# Importing Virgil Key

This guide shows how to export a **Virgil Key** from a Base64 encoded string representation.

Set up your project environment before you begin to import a Virgil Key, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To import a Virgil Key, we need to:

- Initialize **Virgil SDK**

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

- Choose a Base64 encoded string
- Import the Virgil Key from the Base64 encoded string

```java
// initialize a buffer from base64 encoded string
VirgilBuffer aliceKeyBuffer = VirgilBuffer.from("[BASE64_ENCODED_VIRGIL_KEY]",
    StringEncoding.Base64);

// import Virgil Key from buffer
VirgilKey aliceKey = virgil.getKeys().importKey(aliceKeyBuffer,
    "[OPTIONAL_KEY_PASSWORD]");
```
