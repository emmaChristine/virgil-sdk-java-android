package com.virgilsecurity.secureenclave.model.asn1;

import android.util.Log;

import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.secureenclave.exceptions.ASN1Exception;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;

public class VirgilSign implements ASN1Encodable {

    private byte[] sign;

    public VirgilSign(byte[] sign) {
        this.sign = sign;
    }

    public VirgilSign(ASN1Encodable asn1) throws ASN1Exception {
        ASN1Sequence seqInfo = ASN1Sequence.getInstance(asn1);

        AlgorithmIdentifier alg = AlgorithmIdentifier.getInstance(seqInfo.getObjectAt(0));
        if (!alg.getAlgorithm().getId().equals(NISTObjectIdentifiers.id_sha384.getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }
        sign = ASN1OctetString.getInstance(seqInfo.getObjectAt(1)).getOctets();
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return
                new DERSequence(new ASN1Encodable[]{
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE),
                        new DEROctetString(sign)}
                );
    }

    public byte[] getSign() {
        return sign;
    }

    public static VirgilSign getInstance(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            if (obj instanceof byte[]) {
                return new VirgilSign(ASN1Sequence.fromByteArray((byte[]) obj));
            }
            if (obj instanceof VirgilSign) {
                return (VirgilSign) obj;
            }
            return new VirgilSign(ASN1Sequence.getInstance(obj));
        } catch (IOException e) {
            throw new VirgilException(e);
        }
    }

}