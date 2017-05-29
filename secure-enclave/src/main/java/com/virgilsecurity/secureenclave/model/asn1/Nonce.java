package com.virgilsecurity.secureenclave.model.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.virgilsecurity.secureenclave.exceptions.ASN1Exception;

/**
 * Created by Andrii Iakovenko.
 */

public class Nonce implements ASN1Encodable {

    private byte[] content;

    public Nonce( byte[] content) {
        this.content = content;
    }

    public Nonce(ASN1Sequence asn1Sequence) throws ASN1Exception {
        EncryptedContentInfo info = EncryptedContentInfo.getInstance(asn1Sequence);
        if(! PKCSObjectIdentifiers.data.getId().equals(info.getContentType().getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }

        if(! NISTObjectIdentifiers.id_aes256_GCM.getId().equals(info.getContentEncryptionAlgorithm().getAlgorithm().getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }
        this.content = ((DEROctetString) info.getContentEncryptionAlgorithm().getParameters()).getOctets();
    }

    public ASN1Primitive toASN1Primitive() {
        AlgorithmIdentifier algo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_GCM,
                new DEROctetString(this.content));
        return new EncryptedContentInfo(PKCSObjectIdentifiers.data, algo, null).toASN1Primitive();
    }

    public static Nonce getInstance(Object obj) throws ASN1Exception {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Nonce) {
            return (Nonce) obj;
        }
        return new Nonce(ASN1Sequence.getInstance(obj));
    }

    public byte[] getContent() {
        return content;
    }
}
