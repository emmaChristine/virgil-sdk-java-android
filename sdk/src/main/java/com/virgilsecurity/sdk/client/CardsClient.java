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

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.management.relation.RelationException;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.SignableRequestModel;
import com.virgilsecurity.sdk.client.model.cards.CardModel;
import com.virgilsecurity.sdk.client.model.cards.CardScope;
import com.virgilsecurity.sdk.client.model.cards.SearchCriteria;
import com.virgilsecurity.sdk.client.model.cards.SearchRequest;
import com.virgilsecurity.sdk.client.requests.CreateCardRelationRequest;
import com.virgilsecurity.sdk.client.requests.CreateGlobalCardRequest;
import com.virgilsecurity.sdk.client.requests.CreateUserCardRequest;
import com.virgilsecurity.sdk.client.requests.RemoveCardRelationRequest;
import com.virgilsecurity.sdk.client.requests.RevokeCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeGlobalCardRequest;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class CardsClient extends VirgilClient {

    private CardValidator cardValidator;

    /**
     * Create a new instance of {@code CardsClient}
     *
     * @param accessToken
     *            the access token.
     */
    public CardsClient(String accessToken) {
        super(new CardsClientContext(accessToken));
    }

    /**
     * Create a new instance of {@code CardsClient}
     *
     * @param context
     *            the cards client context.
     */
    public CardsClient(CardsClientContext context) {
        super(context);
    }

    /**
     * Publishes card in Virgil Cards service.
     * 
     * TODO: create user card usage
     * 
     * @param request
     *            the create card request.
     * @return the card that is published to Virgil Security services.
     * @throws VirgilServiceException
     *             if an error occurred.
     */
    public CardModel createUserCard(CreateUserCardRequest request) throws VirgilServiceException {
        try {
            URL url = new URL(getContext().getCardsServiceURL(), "/v4/card");

            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            CardModel cardModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Publishes Global card in Virgil cards service.
     * 
     * TODO: create global card usage
     * 
     * @param request
     *            The create card request.
     * @return the global card that is published to Virgil Security services.
     * @throws VirgilServiceException
     *             if an error occurred.
     */
    public CardModel createGlobalCard(CreateGlobalCardRequest request) {
        try {
            URL url = new URL(getContext().getRaServiceURL(), "/v1/card");

            SignableRequestModel requestModel = request.getRequestModel();

            String body = ConvertionUtils.getGson().toJson(requestModel);

            CardModel cardModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Get card by identifier.
     * 
     * TODO: get card usage.
     * 
     * @param cardId
     *            the card identifier.
     * @return the card loaded from Virgil service.
     */
    public CardModel getCard(String cardId) {
        try {
            URL url = new URL(getContext().getReadOnlyCardsServiceURL(), "/v4/card/" + cardId);

            CardModel cardModel = execute(url, "GET", null, CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;

        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Revoke a card from Virgil Services.
     * 
     * TODO: revoke user card usage.
     * 
     * @param request
     *            the revoke card request.
     */
    public void revokeUserCard(RevokeCardRequest request) {
        try {
            URL url = new URL(getContext().getCardsServiceURL(), "/v4/card/" + request.getCardId());
            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            execute(url, "DELETE", new ByteArrayInputStream(ConvertionUtils.toBytes(body)), Void.class);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Revoke Global card.
     * 
     * TODO: revoke global card usage
     * 
     * @param request
     *            an instance of {@link RevokeGlobalCardRequest} class that contains Global Card id and Validation Token
     */
    public void revokeGlobalCard(RevokeGlobalCardRequest request) {
        try {
            URL url = new URL(getContext().getRaServiceURL(), "/v1/card/" + request.getCardId());

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
     * TODO: search cards usage
     * 
     * @param criteria
     *            the criteria for search.
     * @return the found cards list.
     * @throws CardValidationException
     */
    public List<CardModel> searchCards(SearchCriteria criteria) throws CardValidationException {
        if (criteria == null) {
            throw new NullArgumentException("criteria");
        }

        if (criteria.getIdentities().isEmpty()) {
            throw new EmptyArgumentException("criteria");
        }

        SearchRequest request = new SearchRequest();

        request.setIdentities(criteria.getIdentities());

        if (!StringUtils.isBlank(criteria.getIdentityType())) {
            request.setIdentityType(criteria.getIdentityType());
        }

        if (criteria.getScope() == CardScope.GLOBAL) {
            request.setScope(criteria.getScope());
        }

        try {
            URL url = new URL(getContext().getReadOnlyCardsServiceURL(), "/v4/card/actions/search");
            String body = ConvertionUtils.getGson().toJson(request);

            CardModel[] cardModels = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel[].class);

            List<CardModel> cards = Arrays.asList(cardModels);
            validateCards(cards);

            return cards;

        } catch (VirgilServiceException e) {
            throw e;
        } catch (CardValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Adds a relation for the Virgil Card to Virgil cards service.
     * 
     * TODO: create card relation usage.
     * 
     * @param request
     *            An instance of {@link CreateCardRelationRequest} class, that contains a trusted card snapshot.
     * @return Updated {@link CardModel} from server response.
     * @throws CardValidationException
     * @throws RelationException
     */
    public CardModel createCardRelation(CreateCardRelationRequest request)
            throws CardValidationException, RelationException {
        if (request == null || request.getSnapshot() == null || request.getSignatures().size() != 1) {
            throw new RelationException();
        }
        String cardId = request.getSignatures().keySet().iterator().next();

        try {
            URL url = new URL(getContext().getCardsServiceURL(), "/v4/card/" + cardId + "/collections/relations");
            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            CardModel cardModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (CardValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Deletes a relation for the Virgil Card to Virgil cards service.
     * 
     * TODO: remove card relation usage.
     * 
     * @param request
     *            An instance of {@link DeleteRelationRequest} class, /// that contains a trusted card id to be deleted
     *            from relations.
     * @return Updated {@link CardModel} from server response.
     * @throws CardValidationException
     * @throws RelationException
     */
    public CardModel removeCardRelation(RemoveCardRelationRequest request)
            throws CardValidationException, RelationException {
        if (request == null || request.getSnapshot() == null || request.getSignatures().size() != 1) {
            throw new RelationException();
        }
        String cardId = request.getSignatures().keySet().iterator().next();

        try {
            URL url = new URL(getContext().getCardsServiceURL(), "/v4/card/" + cardId + "/collections/relations");
            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            CardModel cardModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (CardValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    private void validateCards(Collection<CardModel> cards) throws CardValidationException {
        if (this.cardValidator == null) {
            return;
        }
        List<CardModel> invalidCards = new ArrayList<>();

        for (CardModel card : cards) {
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

    private CardsClientContext getContext() {
        return (CardsClientContext) this.context;
    }

}
