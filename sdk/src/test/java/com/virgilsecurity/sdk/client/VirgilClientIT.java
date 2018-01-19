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
package com.virgilsecurity.sdk.client;

/**
 * Test cases for VIRGIL Client.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilClientIT extends BaseIT {
/*
    private Crypto crypto;
    private CardClient client;
    private RequestSigner requestSigner;
    private PrivateKey appKey;

    @Before
    public void setUp() throws MalformedURLException, CryptoException {
        crypto = new VirgilCrypto();

        VirgilClientContext ctx = new VirgilClientContext(APP_TOKEN);

        String url = getPropertyByName("CARDS_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setCardsServiceURL(new URL(url));
        }
        url = getPropertyByName("RO_CARDS_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setReadOnlyCardsServiceURL(new URL(url));
        }
        url = getPropertyByName("IDENTITY_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setIdentityServiceURL(new URL(url));
        }

        client = new CardClient(ctx);
        requestSigner = new RequestSigner(crypto);

        appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);
    }

    @Test
    public void testCustomCards() throws VirgilException {
        KeyPair aliceKeys = crypto.generateKeys();

        // Create card
        byte[] exportedPublicKey = crypto.exportPublicKey(aliceKeys.getPublicKey());
        PublishCardRequest createCardRequest = new PublishCardRequest("alice", "username", exportedPublicKey);

        CardModel aliceCard = null;
        try {
            requestSigner.selfSign(createCardRequest, aliceKeys.getPrivateKey());
            requestSigner.authoritySign(createCardRequest, APP_ID, appKey);

            aliceCard = client.publishCard(createCardRequest);

            assertNotNull(aliceCard);
            assertNotNull(aliceCard.getIdentifier());
            assertEquals("alice", aliceCard.getSnapshotModel().getIdentity());
            assertEquals("username", aliceCard.getSnapshotModel().getIdentityType());
            assertEquals(CardScope.APPLICATION, aliceCard.getSnapshotModel().getScope());
            assertNotNull(aliceCard.getMeta().getVersion());
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Get card
        try {
            CardModel card = client.getCard(aliceCard.getIdentifier());
            assertNotNull(card);
            assertEquals(aliceCard.getIdentifier(), card.getIdentifier());
            assertEquals("alice", card.getSnapshotModel().getIdentity());
            assertEquals("username", card.getSnapshotModel().getIdentityType());
            assertEquals(CardScope.APPLICATION, card.getSnapshotModel().getScope());
            assertNotNull(card.getMeta().getVersion());
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search by Application bundle
        SearchCriteria criteria = SearchCriteria.byAppBundle(APP_BUNDLE);

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (APP_ID.equals(card.getIdentifier())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by application", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search by getIdentity
        criteria = SearchCriteria.byIdentity("alice");

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (aliceCard.getIdentifier().equals(card.getIdentifier())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by getIdentity", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search by identities
        criteria = SearchCriteria.byIdentities(Arrays.asList("alice", "bob"));

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (aliceCard.getIdentifier().equals(card.getIdentifier())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by identities", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Revoke card
        RevokeCardRequest revokeRequest = new RevokeCardRequest(aliceCard.getIdentifier(), RevocationReason.UNSPECIFIED);

        requestSigner.authoritySign(revokeRequest, APP_ID, appKey);

        try {
            client.revokeCard(revokeRequest);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }
    }
*/
}
