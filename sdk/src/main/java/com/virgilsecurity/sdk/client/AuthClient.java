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

import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.auth.ChallengeMessageModel;
import com.virgilsecurity.sdk.client.model.auth.GetChallengeMessageRequestModel;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class AuthClient extends VirgilClient {

    /**
     * Create new instance of {@link AuthClient}.
     */
    public AuthClient() {
        super(new AuthClientContext());
    }

    /**
     * Create new instance of {@link AuthClient}.
     * 
     * @param context
     *            the authentication service context.
     */
    public AuthClient(AuthClientContext context) {
        super(context);
    }

    /**
     * 
     * @param appId
     * @return
     */
    public ChallengeMessageModel getChallengeMessage(String appId) {
        GetChallengeMessageRequestModel model = new GetChallengeMessageRequestModel(appId);

        try {
            URL url = new URL(getContext().getAuthServiceAddressURL(),
                    "/v4/authorization-grant/actions/get-challenge-message");

            String body = ConvertionUtils.getGson().toJson(model);

            ChallengeMessageModel messageModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), ChallengeMessageModel.class);

            return messageModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    private AuthClientContext getContext() {
        return (AuthClientContext) this.context;
    }

}
