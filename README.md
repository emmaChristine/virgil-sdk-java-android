# Virgil Security Java/Android SDK

[Installation](#installation) | [Encryption Example](#encryption-example) | [Initialization](#initialization) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

For a full overview head over to our Java/Android [Get Started][_getstarted] guides.

## Installation

The Virgil SDK is provided as set of packages named *com.virgilsecurity.sdk*. Packages are distributed via Maven repository.

### Target

* Java 7+.
* Android API 16+.

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

__Next:__ [Get Started with the Java/Android SDK][_getstarted].

## Encryption Example

Virgil Security makes it super easy to add encryption to any application. With our SDK you create a public [__Virgil Card__][_guide_virgil_cards] for every one of your users and devices. With these in place you can easily encrypt any data in the client.

```java
// find Alice's card(s)
VirgilCards aliceCards = virgil.getCards().find("alice");

// encrypt the message using Alice's cards
String message = "Hello Alice!";
VirgilBuffer cipherData = aliceCards.encrypt(message);

var message = 
var encryptedMessage = aliceCards.Encrypt(message);

// transmit the message with your preferred technology
String transferData = encryptedMessage.toString(StringEncoding.Base64);
```

The receiving user then uses their stored __private key__ to decrypt the message.


```java
// load Alice's Key from storage.
VirgilKey aliceKey = virgil.getKeys().load("alice_key_1", "mypassword");

// decrypt the message using the key
VirgilBuffer originalData = aliceKey.decrypt(encryptedData);
String originalMessage = originalData.toString();
```

__Next:__ To [get you properly started][_guide_encryption] you'll need to know how to create and store Virgil Cards. Our [Get Started guide][_guide_encryption] will get you there all the way.

__Also:__ [Encrypted communication][_getstarted_encryption] is just one of the few things our SDK can do. Have a look at our guides on  [Encrypted Storage][_getstarted_storage], [Data Integrity][_getstarted_data_integrity] and [Passwordless Login][_getstarted_passwordless_login] for more information.

## Initialization

To use this SDK you need to [sign up for an account](https://developer.virgilsecurity.com/account/signup) and create your first __application__. Make sure to save the __app id__, __private key__ and it's __password__. After this, create an __application token__ for your application to make authenticated requests from your clients.

To initialize the SDK on the client side you will only need the __access token__ you created.

```java
VirgilApi virgil = new VirgilApiImpl("[ACCESS_TOKEN]");
```

> __Note:__ this client will have limited capabilities. For example, it will be able to generate new __Cards__ but it will need a server-side client to transmit these to Virgil.

To initialize the SDK on the server side we will need the __access token__, __app id__ and the __App Key__ you created on the [Developer Dashboard](https://developer.virgilsecurity.com/).

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

## Documentation

Virgil Security has a powerful set of APIs, and the documentation is there to get you started today.

* [Get Started][_getstarted_root] documentation
  * [Initialize the SDK][_initialize_root]
  * [Encrypted storage][_getstarted_storage]
  * [Encrypted communication][_getstarted_encryption]
  * [Data integrity][_getstarted_data_integrity]
  * [Passwordless login][_getstarted_passwordless_login]
* [Guides][_guides]
  * [Virgil Cards][_guide_virgil_cards]
  * [Virgil Keys][_guide_virgil_keys]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email](support).

[support]: mailto:support@virgilsecurity.com
[_getstarted_root]: https://virgilsecurity.com/docs/sdk/java-android/
[_getstarted]: https://virgilsecurity.com/docs/sdk/java-android/getting-started
[_getstarted_encryption]: https://virgilsecurity.com/docs/use-cases/encrypted-communication
[_getstarted_storage]: https://virgilsecurity.com/docs/use-cases/secure-data-at-rest
[_getstarted_data_integrity]: https://virgilsecurity.com/docs/use-cases/data-verification
[_getstarted_passwordless_login]: https://virgilsecurity.com/docs/use-cases/passwordless-authentication
[_guides]: https://virgilsecurity.com/docs/sdk/java-android/features
[_guide_initialization]: https://virgilsecurity.com/docs/sdk/java-android/getting-started#initializing
[_guide_virgil_cards]: https://virgilsecurity.com/docs/sdk/java-android/features#virgil-cards
[_guide_virgil_keys]: https://virgilsecurity.com/docs/sdk/java-android/features#virgil-keys
[_guide_encryption]: https://virgilsecurity.com/docs/sdk/java-android/features#encryption
[_initialize_root]: https://virgilsecurity.com/docs/sdk/java-android/programming-guide#initializing
