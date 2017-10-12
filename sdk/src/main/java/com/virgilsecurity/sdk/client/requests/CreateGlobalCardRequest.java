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
package com.virgilsecurity.sdk.client.requests;

import com.virgilsecurity.sdk.client.model.SignableRequestModel;
import com.virgilsecurity.sdk.client.model.SignableRequestValidationModel;
import com.virgilsecurity.sdk.client.model.cards.CardScope;
import com.virgilsecurity.sdk.client.model.cards.GlobalCardIdentityType;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class CreateGlobalCardRequest extends CreateCardRequest {

    private String validationToken;

    /**
     * Create new instance of {@link CreateGlobalCardRequest}.
     */
    public CreateGlobalCardRequest() {
        this.identityType = GlobalCardIdentityType.EMAIL.getValue();
        this.scope = CardScope.GLOBAL;
    }

    @Override
    public SignableRequestModel getRequestModel() {
        SignableRequestModel requestModel = this.takeSignableRequestModel();

        if (!StringUtils.isBlank(this.validationToken)) {
            requestModel.getMeta().setValidation(new SignableRequestValidationModel(this.validationToken));
        }

        return requestModel;
    }

    public GlobalCardIdentityType getIdentityType() {
        return GlobalCardIdentityType.fromString(this.identityType);
    }

    public void setIdentityType(String value) {
        checkNoSnapshot();
        this.identityType = GlobalCardIdentityType.fromString(value).getValue();
    }

    /**
     * @return the validationToken
     */
    public String getValidationToken() {
        return validationToken;
    }

    /**
     * @param validationToken
     *            the validationToken to set
     */
    public void setValidationToken(String validationToken) {
        this.validationToken = validationToken;
    }

}
