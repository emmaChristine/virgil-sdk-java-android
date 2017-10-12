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
package com.virgilsecurity.sdk.client;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.util.Map;

import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.cards.GlobalCardIdentityType;
import com.virgilsecurity.sdk.client.model.identity.ConfirmEmailModel;
import com.virgilsecurity.sdk.client.model.identity.IdentityConfirmationRequestModel;
import com.virgilsecurity.sdk.client.model.identity.IdentityValidationRequestModel;
import com.virgilsecurity.sdk.client.model.identity.IdentityVerificationRequestModel;
import com.virgilsecurity.sdk.client.model.identity.Token;
import com.virgilsecurity.sdk.client.model.identity.VerifyEmailModel;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class IdentityClient extends VirgilClient {

    /**
     * Create new instance of {@link IdentityClient}.
     */
    public IdentityClient() {
        super(new IdentityClientContext());
    }

    /**
     * Create new instance of {@link IdentityClient}.
     * 
     * @param context
     *            the context.
     */
    public IdentityClient(IdentityClientContext context) {
        super(context);
    }

    /**
     * Sends the request for identity verification, that's will be processed depending of specified type.
     * 
     * @param identity
     *            an unique string that represents identity.
     * @return the action identifier that is required for confirmation the identity.
     * 
     * @see #confirmIdentity(String, String, Token)
     */
    public VerifyEmailModel verifyEmail(String identity) {
        return verifyEmail(identity, null);
    }

    /**
     * Sends the request for identity verification, that's will be processed depending of specified type.
     * 
     * @param identity
     *            An unique string that represents identity.
     * @param extraFields
     *            The extra fields.
     * @return the action identifier that is required for confirmation the identity.
     * 
     * @see #confirmIdentity(String, String, Token)
     */
    public VerifyEmailModel verifyEmail(String identity, Map<String, String> extraFields) {
        IdentityVerificationRequestModel requestModel = new IdentityVerificationRequestModel(identity,
                GlobalCardIdentityType.EMAIL.getValue(), extraFields);

        try {
            URL url = new URL(getContext().getIdentityServiceURL(), "v1/verify");

            String body = ConvertionUtils.getGson().toJson(requestModel);

            VerifyEmailModel responseModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), VerifyEmailModel.class);
            return responseModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Confirms the identity from the verify step to obtain an identity confirmation token.
     * 
     * @param actionId
     *            the action identifier.
     * @param confirmationCode
     *            the confirmation code.
     * @return the instance of {@link ConfirmEmailModel} that represent an identity validation token.
     */
    public ConfirmEmailModel confirmEmail(String actionId, String confirmationCode) {
        return confirmEmail(actionId, confirmationCode, new Token(3600, 1));
    }

    /**
     * Confirms the identity from the verify step to obtain an identity confirmation token.
     * 
     * @param actionId
     *            the action identifier.
     * @param confirmationCode
     *            the confirmation code.
     * @param confirmationToken
     *            the confirmation token.
     * @return the instance of {@link ConfirmEmailModel} that represent an identity validation token.
     */
    public ConfirmEmailModel confirmEmail(String actionId, String confirmationCode, Token confirmationToken) {
        IdentityConfirmationRequestModel requestModel = new IdentityConfirmationRequestModel(actionId, confirmationCode,
                confirmationToken);

        try {
            URL url = new URL(getContext().getIdentityServiceURL(), "v1/confirm");

            String body = ConvertionUtils.getGson().toJson(requestModel);

            ConfirmEmailModel responseModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), ConfirmEmailModel.class);
            return responseModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Checks validated token.
     * 
     * @param identity
     *            The value of identity.
     * @param validationToken
     *            The validation token.
     * @return {@code true} if validation token is valid.
     */
    public boolean validateToken(String identity, String validationToken) {
        IdentityValidationRequestModel requestModel = new IdentityValidationRequestModel(identity,
                GlobalCardIdentityType.EMAIL.getValue(), validationToken);

        try {
            URL url = new URL(getContext().getIdentityServiceURL(), "v1/validate");

            String body = ConvertionUtils.getGson().toJson(requestModel);

            execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)), Void.class);
            return true;
        } catch (VirgilServiceException e) {
            return false;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    private IdentityClientContext getContext() {
        return (IdentityClientContext) this.context;
    }

}
