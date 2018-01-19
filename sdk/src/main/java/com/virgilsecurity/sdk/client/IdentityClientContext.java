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

import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author Andrii Iakovenko
 *
 */
public class IdentityClientContext extends VirgilClientContext {

    private URL identityServiceURL;

    /**
     * Create new instance of {@link IdentityClientContext}.
     */
    public IdentityClientContext() {
        init();
    }

    /**
     * Create new instance of {@link IdentityClientContext}.
     * 
     * @param accessToken
     */
    public IdentityClientContext(String accessToken) {
        super(accessToken);
        init();
    }

    /**
     * @return the identityServiceURL
     */
    public URL getIdentityServiceURL() {
        return identityServiceURL;
    }

    /**
     * @param identityServiceURL
     *            the identityServiceURL to set
     */
    public void setIdentityServiceURL(URL identityServiceURL) {
        this.identityServiceURL = identityServiceURL;
    }

    private void init() {
        try {
            this.identityServiceURL = new URL("https://getIdentity.virgilsecurity.com");
        } catch (MalformedURLException e) {
            // This should never happen
        }
    }

}
