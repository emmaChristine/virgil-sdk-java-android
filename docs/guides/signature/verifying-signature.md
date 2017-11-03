# Verifying Signature

This guide is a short tutorial on how to verify a **Digital Signature** with Virgil Security.

For original information about the Digital Signature follow the link [here](https://github.com/VirgilSecurity/virgil/blob/wiki/wiki/glossary.md#digital-signature).

Set up your project environment before starting to verify a Digital Signature, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

The Signature Verification procedure is shown in the figure below.


![Virgil Signature Intro](/docs/img/Signature_introduction.png "Verify Signature")

To verify the Digital Signature, Bob needs Alice's **Virgil Card"**.

Let's review the Digital Signature verification process:

- Developers initialize the **Virgil SDK**

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

- Bob takes Alice's **Virgil Card ID** and searches for Alice's Virgil Card on **Virgil Services**
- Bob verifies the signature. If the signature is invalid, Bob will receive an error message.

```java
// search for Virgil Card
VirgilCard aliceCard = virgil.getCards().get("[ALICE_CARD_ID_HERE]");

// verify signature using Alice's Virgil Card
if (!aliceCard.verify(message, signature)) {
    throw new Exception("Aha... Alice it's not you.");
}
```

See our guide on [Validating Cards](/docs/guides/virgil-card/validating-card.md) for the best practices.
