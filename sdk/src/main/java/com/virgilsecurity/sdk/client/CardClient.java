/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.RawSignedModel;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.List;


public class CardClient {

    private URL baseUrl;
    private HttpClient httpClient;

    /**
     * Create a new instance of {@code CardClient}
     */
    public CardClient(URL baseUrl) {
        this.baseUrl = baseUrl;
        httpClient = new HttpClient();
    }

    /**
     * Get card by identifier.
     *
     * @param cardId the card identifier.
     * @param token  token to authorize the request.
     * @return the card loaded from VIRGIL Cards service.
     */
    public RawSignedModel getCard(String cardId, String token) {
        try {
            URL url = new URL(baseUrl, "card/" + cardId);

            return httpClient.execute(url,
                                      "GET",
                                      token,
                                      null,
                                      RawSignedModel.class);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Publishes card in VIRGIL Cards service.
     *
     * @param rawCard the create card request.
     * @param token   token to authorize the request.
     * @return the card that is published to VIRGIL Cards service.
     * @throws VirgilServiceException if an error occurred.
     */
    public RawSignedModel publishCard(RawSignedModel rawCard, String token) throws VirgilServiceException {
        try {
            URL url = new URL(baseUrl, "card");
            String body = rawCard.exportAsJson();

            return httpClient.execute(url,
                                      "POST",
                                      token,
                                      new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                                      RawSignedModel.class);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Search cards by criteria.
     *
     * @param identity the identity for search.
     * @param token    token to authorize the request.
     * @return the found cards list.
     */
    public List<RawSignedModel> searchCards(String identity, String token) {
        if (identity == null)
            throw new NullArgumentException("CardClient -> 'identity' should not be null");

        if (identity.isEmpty())
            throw new EmptyArgumentException("CardClient -> 'identity' should not be empty");

        try {
            URL url = new URL(baseUrl, "card/actions/search");
            String body = "{\"identity\":\"" + identity + "\"}";

            RawSignedModel[] cardModels =
                    httpClient.execute(url,
                                       "POST",
                                       token,
                                       new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                                       RawSignedModel[].class);

            return Arrays.asList(cardModels);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }
}
