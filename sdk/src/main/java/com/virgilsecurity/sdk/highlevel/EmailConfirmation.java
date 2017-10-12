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
package com.virgilsecurity.sdk.highlevel;

import com.virgilsecurity.sdk.client.IdentityClient;
import com.virgilsecurity.sdk.client.model.identity.ConfirmEmailModel;
import com.virgilsecurity.sdk.client.model.identity.Token;

/**
 * @author Andrii Iakovenko
 *
 */
public class EmailConfirmation extends IdentityConfirmation {

    private String confirmationCode;

    /**
     * Create new instance of {@link EmailConfirmation}.
     * 
     * @param confirmationCode
     *            The confirmation code from email.
     */
    public EmailConfirmation(String confirmationCode) {
        super();
        this.confirmationCode = confirmationCode;
    }

    @Override
    String confirmAndGrabValidationToken(IdentityVerificationAttempt attempt, IdentityClient client) {
        Token token = new Token(attempt.getTimeToLive(), attempt.getCountToLive());
        ConfirmEmailModel confirmatonToken = client.confirmEmail(attempt.getActionId(), this.confirmationCode, token);

        return confirmatonToken.getValidationToken();
    }

}
