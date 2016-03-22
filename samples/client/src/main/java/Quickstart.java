
/*
 * Copyright (c) 2016, Virgil Security, Inc.
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonObject;
import com.virgilsecurity.sdk.client.ClientFactory;
import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.client.model.identity.ValidatedIdentity;
import com.virgilsecurity.sdk.client.model.publickey.SearchCriteria.Builder;
import com.virgilsecurity.sdk.client.model.publickey.VirgilCard;
import com.virgilsecurity.sdk.client.model.publickey.VirgilCardTemplate;
import com.virgilsecurity.sdk.crypto.CryptoHelper;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.KeyPairGenerator;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;

/**
 * This sample will help you get started using the Crypto Library and Virgil
 * Keys Services for the most popular platforms and languages.
 * 
 * @author Andrii Iakovenko
 *
 */
public class Quickstart {

	public static void main(String[] args) throws Exception {
		String accesToken = "{ACCESS_TOKEN}";
		ClientFactory factory = new ClientFactory(accesToken);

		// Step 1. Create and Publish the Keys

		/**
		 * First a mail exchange application is generating the keys and
		 * publishing them to the Public Keys Service where they are available
		 * in an open access for other users (e.g. recipient) to verify and
		 * encrypt the data for the key owner. The following code example
		 * creates a new public/private key pair.
		 */

		String password = "jUfreBR7";
		// the private key's password is optional
		KeyPair keyPair = KeyPairGenerator.generate(password);

		/*
		 * The app is verifying whether the user really owns the provided email
		 * address and getting a temporary token for public key registration on
		 * the Public Keys Service.
		 */
		String actionId = factory.getIdentityClient().verify(IdentityType.EMAIL, "sender-test@virgilsecurity.com");
		// use confirmation code sent to your email box.
		ValidatedIdentity identity = factory.getIdentityClient().confirm(actionId, "{CONFIRMATION_CODE}");

		/*
		 * The app is registering a Virgil Card which includes a public key and
		 * an email address identifier. The card will be used for the public key
		 * identification and searching for it in the Public Keys Service.
		 */

		VirgilCardTemplate.Builder vcBuilder = new VirgilCardTemplate.Builder().setIdentity(identity)
				.setPublicKey(keyPair.getPublic());
		VirgilCard senderCard = factory.getPublicKeyClient().createCard(vcBuilder.build(), keyPair.getPrivate());

		// Step 2. Encrypt and Sign

		/*
		 * The app is searching for the recipient’s public key on the Public
		 * Keys Service to encrypt a message for him. The app is signing the
		 * encrypted message with sender’s private key so that the recipient can
		 * make sure the message had been sent from the declared sender.
		 */

		String message = "Encrypt me, Please!!!";

		Builder criteriaBuilder = new Builder().setValue("recipient-test@virgilsecurity.com");
		List<VirgilCard> recipientCards = factory.getPublicKeyClient().search(criteriaBuilder.build());

		Map<String, PublicKey> recipients = new HashMap<>();
		for (VirgilCard card : recipientCards) {
			recipients.put(card.getId(), new PublicKey(card.getPublicKey().getKey()));
		}

		String encryptedMessage = CryptoHelper.encrypt(message, recipients);
		String signature = CryptoHelper.sign(encryptedMessage, keyPair.getPrivate());

		// Step 3. Send an Email

		/*
		 * The app is merging the message and the signature into one structure
		 * and sending the letter to the recipient using a simple mail client.
		 */
		JsonObject encryptedBody = new JsonObject();
		encryptedBody.addProperty("Content", encryptedMessage);
		encryptedBody.addProperty("Signature", signature);

		// Step 4. Receive an Email

		/*
		 * An encrypted letter is received on the recipient’s side using a
		 * simple mail client.
		 */

		// Step 5. Get Sender’s Card

		/*
		 * In order to decrypt the received data the app on recipient’s side
		 * needs to get sender’s Virgil Card from the Public Keys Service.
		 */

		criteriaBuilder = new Builder().setValue("sender-test@virgilsecurity.com");
		senderCard = factory.getPublicKeyClient().search(criteriaBuilder.build()).get(0);

		// Step 6. Verify and Decrypt
		/*
		 * We are making sure the letter came from the declared sender by
		 * getting his card on Public Keys Service. In case of success we are
		 * decrypting the letter using the recipient’s private key.
		 */

		PrivateKey recipientPrivateKey = new PrivateKey("{RECIPIENT_KEY}");

		String encryptedContent = encryptedBody.get("Content").getAsString();
		String encryptedContentSignature = encryptedBody.get("Signature").getAsString();
		boolean isValid = CryptoHelper.verify(encryptedContent, encryptedContentSignature,
				new PublicKey(senderCard.getPublicKey().getKey()));
		if (!isValid) {
			throw new Exception("Signature is not valid.");
		}

		String originalMessage = CryptoHelper.decrypt(encryptedContent, "{RECIPIENT_CARD_ID}", recipientPrivateKey);
	}

}
