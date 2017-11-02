# Virgil Security Java/Android SDK

[Installation](#installation) | [Initialization](#initialization) | [Encryption / Decryption Example](#encryption-example) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few steps, you can encrypt communication, securely store data, provide passwordless authentication, and ensure data integrity.

To initialize and use Virgil SDK, you need to have [Developer Account](https://developer.virgilsecurity.com/account/signin).


## Installation

The Virgil SDK is provided as set of packages named *com.virgilsecurity.sdk*. Packages are distributed via Maven repository.

### Target

* Java 7+
* Android API 16+

### Prerequisites

* Java Development Kit (JDK) 7+
* Maven 3+

### Installing the package

You can easily add SDK dependency to your project, just follow the examples below:

#### Maven

Use this packages for Java projects.

```
<dependency>
    <groupId>com.virgilsecurity.sdk</groupId>
    <artifactId>crypto</artifactId>
    <version>4.3.3</version>
</dependency>
<dependency>
    <groupId>com.virgilsecurity.sdk</groupId>
    <artifactId>sdk</artifactId>
    <version>4.3.3</version>
</dependency>
```

#### Gradle

Use this packages for Android projects.

```
compile 'com.virgilsecurity.sdk:crypto-android:4.3.3@aar'
compile 'com.virgilsecurity.sdk:sdk-android:4.3.3@aar'
compile 'com.google.code.gson:gson:2.7'
```


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the SDK at the __Client Side__ you need only the __Access Token__ created for a client at [Dev Portal](https://developer.virgilsecurity.com/account/signin). The Access Token helps to authenticate client's requests.

```java
VirgilApi virgil = new VirgilApiImpl("[ACCESS_TOKEN]");
```


To initialize the SDK at the __Server Side__ you need the application credentials (__Access Token__, __App ID__, __App Key__ and __App Key Password__) you got during Application registration at the [Dev Portal](https://developer.virgilsecurity.com/account/signin).

```java
AppCredentials credentials = new AppCredentials();
credentials.setAppId("[YOUR_APP_ID_HERE]");
credentials.setAppKey(VirgilBuffer.from("[YOUR_APP_KEY_PATH_HERE]")));
credentials.setAppKeyPassword("[YOUR_APP_KEY_PASSWORD_HERE]");

VirgilApiContext context = new VirgilApiContext("[YOUR_ACCESS_TOKEN_HERE]");
context.setCredentials(credentials);

VirgilApi virgil = new VirgilApiImpl(context);
```

Next: [Learn more about our the different ways of initializing the Java/Android SDK][_guide_initialization] in our documentation.


## Encryption / Decryption Example

Virgil Security simplifies adding encryption to any application. With our SDK you may create unique Virgil Cards for your all users and devices. With users' Virgil Cards, you can easily encrypt any data at Client Side.

```java
// find Alice's Virgil Card(s) at Virgil Services
VirgilCards aliceCards = virgil.getCards().find("alice");

// encrypt the message using Alice's Virgil Cards
String message = "Hello Alice!";
VirgilBuffer cipherData = aliceCards.encrypt(message);

var message =
var encryptedMessage = aliceCards.Encrypt(message);

// transmit the message with your preferred technology to Alice
String transferData = encryptedMessage.toString(StringEncoding.Base64);
```

Alice uses her Virgil Private Key to decrypt the encrypted message.

```java
// load Alice's Private Virgil Key from local storage.
VirgilKey aliceKey = virgil.getKeys().load("alice_key_1", "mypassword");

// decrypt the message using the Alice's Private Virgil Key
VirgilBuffer originalData = aliceKey.decrypt(encryptedData);
String originalMessage = originalData.toString();
```

__Next:__ On the page below you can find configuration documentation and the list of our guides and use cases where you can see appliance of Virgil Java SDK.


## Documentation

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [Get Started](/docs/get-started) documentation
  * [Encrypted storage](/docs/get-started/encrypted-storage.md)
  * [Encrypted communication](/docs/get-started/encrypted-communication.md)
  * [Data integrity](/docs/get-started/data-integrity.md)
* [Guides](/docs/guides)
  * [Virgil Cards](/docs/guides/virgil-card)
  * [Virgil Keys](/docs/guides/virgil-key)
  * [Encryption](/docs/guides/encryption)
  * [Signature](/docs/guides/signature)
* [Configuration](/docs/guides/configuration)
  * [Set Up Client Side](/docs/guides/configuration/client-configuration.md)
  * [Set Up Server Side](/docs/guides/configuration/server-configuration.md)

__Next__ Also, see our Virgil [Java/Android SDK for PFS](https://github.com/VirgilSecurity/virgil-java-pfs) Encrypted Communication to protect previously intercepted traffic from being decrypted even if the main Private Key is compromised.

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email][support].

[support]: mailto:support@virgilsecurity.com
