# Exporting Card

This guide shows how to export a Virgil Card to the string representation.

Set up your project environment before you begin to export a Virgil Card, with the [getting started](https://github.com/VirgilSecurity/virgil-sdk-java-android/blob/docs-review/docs/guides/configuration/client-configuration.md) guide.

To export a Virgil Card, we need to:

- Initialize the **Virgil SDK**

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

#{ export "initialize_without_token" }

```java
VirgilApi virgil = new VirgilApiImpl();
```

- Use the code below to export the Virgil Card to its string representation.

```java
// export a Virgil Card to string
String exportedAliceCard = aliceCard.export();
```

#{ export "import_card" }
```java
// import a Virgil Card from string
VirgilCard aliceCard = virgil.getCards().importCard(exportedAliceCard);
```

The same mechanism works for **Global Virgil Card**.
