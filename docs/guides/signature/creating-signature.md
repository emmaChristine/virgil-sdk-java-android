# Creating Signature

This guide is a short tutorial on how to create a **Digital Signature** with Virgil Security.
With valid digital signature, recipient is sure that the message was created by a known sender, that the sender cannot deny sending the message, and that the message was not altered in transit. It can be used with any kind of message – whether it is encrypted or not.

See our [Use Cases](https://github.com/VirgilSecurity/virgil-sdk-java-android/tree/docs-review/docs) to find out what you can do with Digital Signature.

Set up your project environment before starting to create a Digital Signature, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

The **Signature Creation** procedure is shown in the figure below.

![Virgil Signature Intro](/docs/img/Signature_introduction.png "Create Signature")

To create a Digital Signature and sign the message, Alice needs her **Virgil Key**.


Let's review the **Digital Signature** creation process:

- Developers need to initialize the **Virgil SDK**

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

- Load Alice's Virgil Key from the protected storage and enter the Virgil Key password;

```java
// load Virgil Key
VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]", "[KEY _PASSWORD]");
```


To load the Virgil Key from a specific storage, developers need to change the storage path during Virgil SDK initialization.

Then Alice has to:
- Prepare the information for the message to Bob
- Sign the message using her Virgil Key

#{ export "create_signature" }
```java
// prepare a message
String message = "Hey Bob, hope you are doing well.";

// generate signature
VirgilBuffer signature = aliceKey.sign(message);
```

See our guide on [Loading Keys](/docs/guides/virgil-key/loading-key.md) for more examples.

Now Alice can send a signed message to Bob.