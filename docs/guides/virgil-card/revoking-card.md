# Revoking Card

This guide shows how to revoke a Virgil Card from Virgil Services.

Set up your project environment before you begin to revoke a Virgil Card, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To revoke a Virgil Card, we need to:

- Initialize the **Virgil SDK** and enter Application **credentials** (**App ID**, **App Key**, **App Key password**)

```java
Crypto crypto = new VirgilCrypto();
VirgilClientContext ctx = new VirgilClientContext(APP_TOKEN);
VirgilClient client = new VirgilClient(ctx);
RequestSigner requestSigner = new RequestSigner(crypto);

// Import application private key
PrivateKey appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(),
    APP_PRIVATE_KEY_PASSWORD);
```

- Get Alice's Virgil Card by **ID** from **Virgil Services**
- Revoke Alice's Virgil Card from Virgil Services

```java
// get a Virgil Card by ID
VirgilCard aliceCard = virgil.getCards().get("[USER_CARD_ID_HERE]");

// revoke a Virgil Card
virgil.getCards().revoke(aliceCard);
```
