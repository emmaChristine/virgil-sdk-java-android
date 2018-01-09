package com.virgilsecurity.sdk.web;

import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.web.contract.AccessManager;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebToken;
import jdk.internal.jline.internal.Nullable;

import java.util.concurrent.*;

public class VirgilAccessManager implements AccessManager {

    private JsonWebToken accessToken;
    private Callable<String> obtainAccessToken;

    public VirgilAccessManager(@Nullable Callable<String> obtainAccessToken) {
        if (obtainAccessToken != null)
            this.obtainAccessToken = obtainAccessToken;
        else
            throw new NullArgumentException("obtainAccessToken should not be null");
    }

    /**
     * Submits obtainAccessToken Callable to obtain JWT
     *
     * @return <code>JsonWebToken</code> if JWT is successfully obtained, otherwise <code>null</code>
     */
    @Override public JsonWebToken getAccessToken() {

        if (accessToken == null || accessToken.isExpired()) {
            ExecutorService executorService = Executors.newSingleThreadExecutor();
            Future<String> accessTokenFuture = executorService.submit(obtainAccessToken);

            try {
                accessToken = JsonWebToken.from(accessTokenFuture.get());
                executorService.shutdownNow();
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
                executorService.shutdownNow();
                accessToken = null;
            }
        }

        return accessToken;
    }
}
