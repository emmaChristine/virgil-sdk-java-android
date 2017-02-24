import java.util.Arrays;

import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.highlevel.EmailConfirmation;
import com.virgilsecurity.sdk.highlevel.IdentityValidationToken;
import com.virgilsecurity.sdk.highlevel.IdentityVerificationAttempt;
import com.virgilsecurity.sdk.highlevel.StringEncoding;
import com.virgilsecurity.sdk.highlevel.VirgilApi;
import com.virgilsecurity.sdk.highlevel.VirgilBuffer;
import com.virgilsecurity.sdk.highlevel.VirgilCard;
import com.virgilsecurity.sdk.highlevel.VirgilKey;
import com.virgilsecurity.sdk.highlevel.impl.AppCredentials;
import com.virgilsecurity.sdk.highlevel.impl.VirgilApiContext;
import com.virgilsecurity.sdk.highlevel.impl.VirgilApiImpl;
import com.virgilsecurity.sdk.highlevel.impl.VirgilCards;

/*
 * Copyright (c) 2017, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @author Andrii Iakovenko
 *
 */
public class HiLevelSample {

    private static final String ACCESS_TOKEN = "{YOUR_ACCESS_TOKEN}";
    private static final String APP_ID = "{YOUR_APP_ID_HERE}";
    private static final String APP_KEY_PASSWORD = "{YOUR_APP_KEY_PASSWORD_HERE}";
    private static final String APP_KEY = "{YOUR_APP_KEY_HERE}";

    private static final String ALICE_KEY_NAME = "ALICE";
    private static final String ALICE_KEY_PWD = "12345678";

    private static final String BOB_KEY_NAME = "BOB";
    private static final String BOB_KEY_PWD = "1234567890";

    public static void main(String[] args) {
        globalCards();
    }

    private static void globalCards() {
        /** Initialize high-level SDK with only application access token */
        VirgilApi virgil = new VirgilApiImpl(ACCESS_TOKEN);

        /** Register Global Virgil Card */
        VirgilKey aliceKey = virgil.getKeys().generate().save(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // create alice's Card using her newly generated Key.
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);
        String aliceCardId = aliceCard.getId();

        // initiate an identity verification process.
        IdentityVerificationAttempt attempt = aliceCard.checkIdentity();

        // confirm a Card's identity using confirmation code retrived on the email.
        IdentityValidationToken token = attempt.confirm(new EmailConfirmation("[CONFIRMATION_CODE]"));

        // publish a Card on the Virgil Security services.
        virgil.getCards().publishGlobal(aliceCard, token);

        /** Revoke Global Virgil Card */
        // load alice's Key from secure storage provided by default.
        aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // load alice's Card from Virgil Security services.
        aliceCard = virgil.getCards().get(aliceCardId);

        // initiate Card's identity verification process.
        attempt = aliceCard.checkIdentity();

        // confirm Card's identity using confirmation code and grub validation token.
        token = attempt.confirm(new EmailConfirmation("[CONFIRMATION_CODE]"));

        // revoke Virgil Card from Virgil Security services.
        virgil.getCards().revokeGlobal(aliceCard, aliceKey, token);
    }

    private static void localCards() {
        /** Register Local Virgil Card */
        // initialize Virgil SDK
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_KEY));
        credentials.setAppKeyPassword(APP_KEY_PASSWORD);

        VirgilApiContext context = new VirgilApiContext(ACCESS_TOKEN);
        context.setCredentials(credentials);

        VirgilApi virgil = new VirgilApiImpl(context);

        // generate and save alice's Key
        VirgilKey aliceKey = virgil.getKeys().generate().save(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // create alice's Card using her Key
        VirgilCard aliceCard = virgil.getCards().create("alice", aliceKey);

        // export alice's Card to string
        String exportedAliceCard = aliceCard.export();

        /** Publish a Virgil Card */
        // import alice's Card from its string representation.
        aliceCard = virgil.getCards().importCard(exportedAliceCard);
        String aliceCardId = aliceCard.getId();

        // verify alice's Card information before publishing it on the Virgil services.

        // aliceCard.getIdentity()
        // aliceCard.getIdentityType()
        // aliceCard.getCustomFields()

        // publish alice's Card on Virgil Services
        virgil.getCards().publish(aliceCard);

        /** Revoke Local Virgil Card */
        // get alice's Card by ID
        aliceCard = virgil.getCards().get(aliceCardId);

        // revoke alice's Card from Virgil Security services.
        virgil.getCards().revoke(aliceCard);
    }

    public static void encryption() {
        /** Initialization */
        // initialize Virgil SDK
        VirgilApi virgil = new VirgilApiImpl(ACCESS_TOKEN);

        /** Encrypt data */
        // search for alice's and bob's Cards
        VirgilCards recipients = virgil.getCards().find(Arrays.asList("alice", "bob"));

        String message = "Hello Guys, let's get outta here.";

        // encrypt message for multiple recipients
        VirgilBuffer cipherData = recipients.encrypt(message);

        String transferData = cipherData.toString(StringEncoding.Base64);
        // var transferData = cipherData.ToString(StringEncoding.Hex);
        // var transferData = cipherData.ToBytes();

        /** Decrypt data */
        // load alice's Key from secure storage provided by default.
        VirgilKey aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // get buffer from base64 encoded string
        VirgilBuffer encryptedData = VirgilBuffer.from(transferData, StringEncoding.Base64);

        // decrypt message using alice's Private key.
        VirgilBuffer originalData = aliceKey.decrypt(encryptedData);

        String originalMessage = originalData.toString();
        // var originalMessage = originalData.ToString(StringEncoding.Base64);
        // var originalMessage = originalData.ToString(StringEncoding.Hex);
        // var originalMessage = originalData.ToBytes(); }
    }

    public static void authenticatedEncryption() {
        /** Initialization */
        // initialize Virgil SDK
        VirgilApi virgil = new VirgilApiImpl(ACCESS_TOKEN);

        /** Sign then Encrypt Data */
        // load alice's key pair from secure storage defined by default
        VirgilKey aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // search for bob's and chris' Cards
        VirgilCards recipients = virgil.getCards().find("bob", "chris");

        String message = "Hello Guys, let's get outta here.";

        // encrypt and sign message for multiple recipients
        VirgilBuffer cipherData = aliceKey.signThenEncrypt(message, recipients);

        String transferData = cipherData.toString(StringEncoding.Base64);

        /** Decrypt then Verify Data */
        // load bob's Key from secure storage defined by default
        VirgilKey bobKey = virgil.getKeys().load(BOB_KEY_NAME, BOB_KEY_PWD);

        // search for alice's Card
        VirgilCards aliceCards = virgil.getCards().find("alice");
        VirgilCard aliceCard = aliceCards.get(0);

        // get buffer from base64 encoded string
        VirgilBuffer encryptedData = VirgilBuffer.from(transferData);

        // decrypt cipher message bob's key pair and verify it using alice's Card
        VirgilBuffer originalData = bobKey.decryptThenVerify(encryptedData, aliceCard);

        String originalMessage = originalData.toString();
    }

    private static void signatures() {
        /** Initialization */
        // initialize Virgil SDK high-level instance
        VirgilApi virgil = new VirgilApiImpl(ACCESS_TOKEN);

        /** Generate Digital Signature */
        // load alice's Key from protected storage
        VirgilKey aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        String message = "Hey Bob, hope you are doing well.";

        // generate signature of message using alice's key pair
        VirgilBuffer signature = aliceKey.sign(message);
        String transferData = signature.toString(StringEncoding.Base64);

        /** Validate Digital Signature */
        // search for alice's Card
        VirgilCards aliceCards = virgil.getCards().find("alice");
        VirgilCard aliceCard = aliceCards.get(0);

        if (!aliceCard.verify(message, signature)) {
            System.out.println("Signature is not valid.");
        }
    }

}
