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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.Card;
import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.model.dto.CreateCardModel;
import com.virgilsecurity.sdk.client.model.dto.ErrorResponse;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.model.dto.SearchRequest;
import com.virgilsecurity.sdk.client.model.dto.SignedResponseModel;
import com.virgilsecurity.sdk.client.model.identity.Identity;
import com.virgilsecurity.sdk.client.model.identity.Token;
import com.virgilsecurity.sdk.client.requests.CreateCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeCardRequest;
import com.virgilsecurity.sdk.client.utils.ConvertionUtils;
import com.virgilsecurity.sdk.client.utils.StreamUtils;
import com.virgilsecurity.sdk.client.utils.StringUtils;
import com.virgilsecurity.sdk.crypto.exceptions.EmptyArgumentException;
import com.virgilsecurity.sdk.crypto.exceptions.NullArgumentException;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilClient {

	private VirgilClientContext context;

	private CardValidator cardValidator;

	/**
	 * Create a new instance of {@code VirgilClient}
	 *
	 * @param accessToken
	 *            the access token.
	 */
	public VirgilClient(String accessToken) {
		this.context = new VirgilClientContext(accessToken);
	}

	/**
	 * Create a new instance of {@code VirgilClient}
	 *
	 * @param context
	 *            the virgil client context.
	 */
	public VirgilClient(VirgilClientContext context) {
		this.context = context;
	}

	/**
	 * Verify identity.
	 * 
	 * @param type
	 *            The type of verified identity.
	 * @param value
	 *            The value of verified identity.
	 * @return action id.
	 */
	@Deprecated
	private String verify(String type, String value) {
		// Implementation removed
		return null;
	}

	/**
	 * Confirms the identity from the {@linkplain #verify(String, String)
	 * verify} step to obtain an identity confirmation token.
	 * 
	 * @param actionId
	 *            the action identifier.
	 * @param confirmationCode
	 *            the confirmation code.
	 * @param confirmationToken
	 *            the confirmation token.
	 * @return
	 * @throws ServiceException
	 */
	@Deprecated
	private Identity confirm(String actionId, String confirmationCode, Token confirmationToken) {
		// Implementation removed
		return null;
	}

	/**
	 * Register a new card.
	 * 
	 * @param request
	 *            the create card request.
	 * @return the created card.
	 * @throws VirgilServiceException
	 *             if an error occurred.
	 */
	public Card createCard(CreateCardRequest request) throws VirgilServiceException {
		try {
			URL url = new URL(context.getCardsServiceURL(), "/v4/card");

			String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

			SignedResponseModel responseModel = execute(url, "POST",
					new ByteArrayInputStream(ConvertionUtils.toBytes(body)), SignedResponseModel.class);
			return responseToCard(responseModel);
		} catch (VirgilServiceException e) {
			throw e;
		} catch (Exception e) {
			throw new VirgilCardServiceException(e);
		}
	}

	/**
	 * Get card by identifier.
	 * 
	 * @param cardId
	 *            the card identifier.
	 * @return the card.
	 */
	public Card getCard(String cardId) {
		try {
			URL url = new URL(context.getReadOnlyCardsServiceURL(), "/v4/card/" + cardId);

			SignedResponseModel responseModel = execute(url, "GET", null, SignedResponseModel.class);
			Card card = responseToCard(responseModel);
			validateCards(Arrays.asList(card));

			return card;

		} catch (VirgilServiceException e) {
			throw e;
		} catch (Exception e) {
			throw new VirgilCardServiceException(e);
		}
	}

	/**
	 * Create and configure http connection.
	 * 
	 * @param url
	 *            The URL.
	 * @param methodName
	 *            The HTTP method.
	 * @return The connection.
	 * @throws IOException
	 */
	private HttpURLConnection createConnection(URL url, String method) throws IOException {
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		urlConnection.setRequestMethod(method);
		urlConnection.setUseCaches(false);

		switch (method) {
		case "DELETE":
		case "POST":
		case "PUT":
		case "PATCH":
			urlConnection.setDoOutput(true);
			urlConnection.setChunkedStreamingMode(0);
			break;
		default:
		}
		urlConnection.setRequestProperty("Authorization", "VIRGIL " + context.getAccessToken());
		urlConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8");

		return urlConnection;
	}

	/**
	 * Revoke existing card.
	 * 
	 * @param request
	 *            the revoke card request.
	 */
	public void revokeCard(RevokeCardRequest request) {
		try {
			URL url = new URL(context.getCardsServiceURL(), "/v4/card/" + request.getCardId());
			String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

			execute(url, "DELETE", new ByteArrayInputStream(ConvertionUtils.toBytes(body)), Void.class);

		} catch (VirgilServiceException e) {
			throw e;
		} catch (Exception e) {
			throw new VirgilCardServiceException(e);
		}
	}

	/**
	 * Search cards by criteria.
	 * 
	 * @param criteria
	 *            the criteria for search.
	 * @return the found cards list.
	 */
	public List<Card> searchCards(SearchCriteria criteria) {
		if (criteria == null) {
			throw new NullArgumentException("criteria");
		}

		if (criteria.getIdentities().isEmpty()) {
			throw new EmptyArgumentException("criteria");
		}

		SearchRequest body = new SearchRequest();

		body.setIdentities(criteria.getIdentities());

		if (!StringUtils.isBlank(criteria.getIdentityType())) {
			body.setIdentityType(criteria.getIdentityType());
		}

		if (criteria.getScope() == CardScope.GLOBAL) {
			body.setScope(criteria.getScope());
		}

		try {
			URL url = new URL(context.getReadOnlyCardsServiceURL(), "/v4/card/actions/search");
			SignedResponseModel[] responseModels = execute(url, "POST",
					new ByteArrayInputStream(ConvertionUtils.toBytes(ConvertionUtils.getGson().toJson(body))),
					SignedResponseModel[].class);

			List<Card> cards = new ArrayList<>();
			for (SignedResponseModel responseModel : responseModels) {
				cards.add(responseToCard(responseModel));
			}

			validateCards(cards);

			return cards;

		} catch (VirgilServiceException e) {
			throw e;
		} catch (Exception e) {
			throw new VirgilCardServiceException(e);
		}
	}

	private Card responseToCard(SignedResponseModel responseModel) {
		CreateCardModel model = ConvertionUtils.getGson()
				.fromJson(ConvertionUtils.base64ToString(responseModel.getContentSnapshot()), CreateCardModel.class);

		Card card = new Card();
		card.setId(responseModel.getCardId());
		card.setSnapshot(ConvertionUtils.base64ToBytes(responseModel.getContentSnapshot()));
		card.setIdentity(model.getIdentity());
		card.setIdentityType(model.getIdentityType());
		card.setPublicKey(ConvertionUtils.base64ToBytes(model.getPublicKey()));

		if (model.getInfo() != null) {
			card.setDevice(model.getInfo().getDevice());
			card.setDeviceName(model.getInfo().getDeviceName());
		}

		if (model.getData() != null) {
			card.setData(Collections.unmodifiableMap(model.getData()));
		}
		card.setScope(model.getScope());
		card.setVersion(responseModel.getMeta().getVersion());

		Map<String, byte[]> signatures = new HashMap<>();
		if ((responseModel.getMeta() != null) && (responseModel.getMeta().getSignatures() != null)) {
			for (Entry<String, String> entry : responseModel.getMeta().getSignatures().entrySet()) {
				signatures.put(entry.getKey(), ConvertionUtils.base64ToBytes(entry.getValue()));
			}
		}

		card.setSignatures(signatures);

		return card;
	}

	/**
	 * @param url
	 * @param methodName
	 * @param class1
	 * @return
	 */
	private <T> T execute(URL url, String method, InputStream inputStream, Class<T> clazz) {
		try {
			HttpURLConnection urlConnection = createConnection(url, method);
			if (inputStream != null) {
				StreamUtils.copyStream(inputStream, urlConnection.getOutputStream());
			}
			try {
				if (urlConnection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
					// Get error code from request
					try (InputStream in = new BufferedInputStream(urlConnection.getErrorStream())) {
						String body = ConvertionUtils.toString(in);
						if (!StringUtils.isBlank(body)) {
							ErrorResponse error = ConvertionUtils.getGson().fromJson(body, ErrorResponse.class);
							throw new VirgilCardServiceException(error.getCode());
						}
					}
					throw new VirgilCardServiceException();
				} else if (clazz.isAssignableFrom(Void.class)) {
					return null;
				} else {
					try (InputStream instream = new BufferedInputStream(urlConnection.getInputStream())) {
						String body = ConvertionUtils.toString(instream);
						return ConvertionUtils.getGson().fromJson(body, clazz);
					}
				}
			} finally {
				urlConnection.disconnect();
			}
		} catch (IOException e) {
			throw new VirgilCardServiceException(e);
		}
	}

	private void validateCards(Collection<Card> cards) {
		if (this.cardValidator == null) {
			return;
		}
		List<Card> invalidCards = new ArrayList<>();

		for (Card card : cards) {
			if (!this.cardValidator.validate(card)) {
				invalidCards.add(card);
			}
		}

		if (!invalidCards.isEmpty()) {
			throw new CardValidationException(invalidCards);
		}
	}

	/**
	 * Sets the card validator.
	 * 
	 * @param cardValidator
	 *            the cardValidator to set
	 */
	public void setCardValidator(CardValidator cardValidator) {
		if (cardValidator == null) {
			throw new NullArgumentException("cardValidator");
		}

		this.cardValidator = cardValidator;
	}

}
