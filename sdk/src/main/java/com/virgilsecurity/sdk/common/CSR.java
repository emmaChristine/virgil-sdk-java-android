package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.web.model.card.RawCardInfo;
import com.virgilsecurity.sdk.web.model.card.RawCardSignature;

import java.util.List;

public class CSR {

    private RawCardInfo info;
    private byte[] snapshot;
    private List<RawCardSignature> signatures;

    public CSR() {
    }


}
