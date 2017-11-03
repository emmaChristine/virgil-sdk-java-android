# Finding Card

This guide shows how to find a Virgil Card. As previously noted, all Virgil Cards are saved at **Virgil Services** after their publication. Thus, every user can find their own Virgil Card or another user's Virgil Card on Virgil Services. It should be noted that users' Virgil Cards will only be visible to application users. Global Virgil Cards will be visible to anybody.

Set up your project environment before you begin to find a Virgil Card, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.


To search for an **Application** or **Global Virgil Card** you need to initialize the **Virgil SDK**:

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```


### Application Cards

There are two ways to find an Application Virgil Card on Virgil Services:

The first one allows developers to get the Virgil Card by its unique **ID**

```java
VirgilCard aliceCard = virgil.getCards().get("[ALICE_CARD_ID]");
```

The second one allows developers to find Virgil Cards by *identity* and *identityType*

```java
// search for all User's Virgil Cards.
VirgilCards aliceCards = virgil.getCards().find("alice");

// search for all User's Virgil Cards with identity type 'member'
VirgilCards bobCards = virgil.getCards().find("member", Arrays.asList("bob"));
```



### Global Cards

```java
// search for all Global Virgil Cards
VirgilCards bobGlobalCards = virgil.getCards()
    .findGlobal("bob@virgilsecurity.com");

// search for Application Virgil Card
VirgilCards appCards = virgil.getCards().findGlobal("com.username.appname");
```
