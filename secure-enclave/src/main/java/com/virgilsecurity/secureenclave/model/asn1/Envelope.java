package com.virgilsecurity.secureenclave.model.asn1;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import com.virgilsecurity.secureenclave.exceptions.ASN1Exception;


/**
 * @author Andrii Iakovenko
 *
 */
public class Envelope implements ASN1Encodable {

    private Collection<ASN1Encodable> recipients;
    private Nonce nonce;
    private Map<String, Object> customParams;

    public Envelope(Collection<ASN1Encodable> recipients, Nonce nonce, Map<String, Object> customParams) {
        this.recipients = recipients;
        this.nonce = nonce;
        this.customParams = customParams;
    }

    public Envelope(ASN1Sequence asn1Sequence) {
        this.customParams = new HashMap<>();
        ASN1Integer v = ASN1Integer.getInstance(asn1Sequence.getObjectAt(0));
        if (v.getValue().intValue() != 0) {
            throw new ASN1ParsingException("Unsupported version");
        }
        ContentInfo info = ContentInfo.getInstance(asn1Sequence.getObjectAt(1));
        if (! PKCSObjectIdentifiers.envelopedData.getId().equals(info.getContentType().getId())) {
            throw new ASN1ParsingException("Unsupported version");
        }
        DERSequence seq = (DERSequence) info.getContent();

        v = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (v.getValue().intValue() != 2) {
            throw new ASN1ParsingException("Unsupported version");
        }

        DERSet recipientsSet = (DERSet) seq.getObjectAt(1);
        List<ASN1Encodable> recipients = new ArrayList<>();
        for (ASN1Encodable recipient : recipientsSet) {
            //TODO check this
            DERTaggedObject tag = (DERTaggedObject) ((DERSequence) recipient).getObjectAt(1);
            if ((tag != null) && (tag.getTagNo() == 3)) {
                recipients.add(PasswordRecipient.getInstance(tag));
            } else if (recipient instanceof DERSequence) {
                recipients.add(PublicKeyRecipient.getInstance(recipient));
            } else {
                throw new ASN1Exception("Unsupported recipient");
            }
        }
        this.recipients = recipients;
        this.nonce = Nonce.getInstance(seq.getObjectAt(2));
        if (asn1Sequence.size() == 3) {
            decodeCustomParams(ASN1TaggedObject.getInstance(asn1Sequence.getObjectAt(2)));
        }

    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(new ContentInfo(PKCSObjectIdentifiers.envelopedData,
                        new DERSequence(
                                new ASN1Encodable[] {
                                        new ASN1Integer(2),
                                        new DERSet(this.recipients.toArray(new ASN1Encodable[0])),
                                        this.nonce})
                )
        );
        if(this.customParams!=null && !this.customParams.isEmpty()) {
            v.add(encodeCustomParam());
        }
        return new DERSequence(v);
    }

    private ASN1Encodable encodeCustomParam() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (Map.Entry<String, Object> p : this.customParams.entrySet()) {
            if (p.getValue() instanceof byte[]) {
                v.add(new DERSequence(
                        new ASN1Encodable[] {
                                new DERUTF8String(p.getKey()),
                                new DERTaggedObject(true, 2, new DEROctetString((byte[]) p.getValue()))
                        })
                );
            } else if (p.getValue() instanceof Integer) {
                v.add(new DERSequence(
                        new ASN1Encodable[] {
                                new DERUTF8String(p.getKey()),
                                new DERTaggedObject(true, 0, new ASN1Integer((int)p.getValue()))
                        })
                );
            }
        }
        return new DERTaggedObject(true, 0, new DERSet(v));
    }


    private void decodeCustomParams(ASN1TaggedObject asn1) {

        if (asn1.getTagNo() != 0) {
            throw new ASN1ParsingException("Unsupported signature formata");
        }
        ASN1Set set = ASN1Set.getInstance(asn1.getObject());
        for (ASN1Encodable item : set) {
            ASN1Sequence seq = ASN1Sequence.getInstance(item);
            DERUTF8String info = DERUTF8String.getInstance(seq.getObjectAt(0));
            String key = info.getString();

            ASN1TaggedObject tag = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
            switch (tag.getTagNo()) {
                case 2:
                    this.customParams.put(key, getByteValue(tag));
                    break;
                case 0:
                    this.customParams.put(key, getIntValue(tag));
                    break;
                default:
                    throw new ASN1Exception("unsupported tag parameter");
            }

        }
    }

    private Integer getIntValue(ASN1TaggedObject tag) {
        return ASN1Integer.getInstance(tag, true).getValue().intValue();
    }

    private Object getByteValue(ASN1TaggedObject tag) {
        return ASN1OctetString.getInstance(tag.getObject()).getOctets();
    }

    public static Envelope getInstance(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Envelope) {
            return (Envelope) obj;
        }
        return new Envelope(ASN1Sequence.getInstance(obj));
    }

    public Collection<ASN1Encodable> getRecipients() {
        return recipients;
    }

    public Map<String, Object> getCustomParams() {
        return customParams;
    }

    public Nonce getNonce() {
        return nonce;
    }
}
