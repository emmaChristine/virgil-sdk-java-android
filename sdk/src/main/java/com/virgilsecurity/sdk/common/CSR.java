package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.common.model.RawCard;
import com.virgilsecurity.sdk.common.model.RawSignature;

import java.util.List;

public class CSR {

    private RawCard info;
    private byte[] snapshot;
    private List<RawSignature> signatures;

    public CSR() {
    }


}
