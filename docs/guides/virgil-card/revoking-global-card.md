# Revoking Global Card

This guide shows how to revoke a **Global Virgil Card**.

Set up your project environment before you begin to revoke a Global Virgil Card, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To revoke a Global Virgil Card, we need to:

-  Initialize the Virgil SDK

```java
Crypto crypto = new VirgilCrypto();
VirgilClientContext ctx = new VirgilClientContext(APP_TOKEN);
VirgilClient client = new VirgilClient(ctx);
RequestSigner requestSigner = new RequestSigner(crypto);

// Import application private key
PrivateKey appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(),
    APP_PRIVATE_KEY_PASSWORD);
```

- Load Alice's Virgil Key from the secure storage provided by default
- Load Alice's Virgil Card from **Virgil Services**
- Initiate the Card identity verification process
- Confirm the Card identity using a **confirmation code**
- Revoke the Global Virgil Card from Virgil Services

```java
// load a Virgil Key from storage
VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]",
    "[OPTIONAL_KEY_PASSWORD]");

// load a Virgil Card from Virgil Services
VirgilCard aliceCard = virgil.getCards().get("[USER_CARD_ID_HERE]");

// initiate an identity verification process.
IdentityVerificationAttempt attempt = aliceCard.checkIdentity();

// grab a validation token
IdentityValidationToken token = attempt
    .confirm(new EmailConfirmation("[CONFIRMATION_CODE]"));

// revoke a Global Virgil Card
virgil.getCards().revokeGlobal(aliceCard, aliceKey, token);
```
