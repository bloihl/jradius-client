package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class ChapPasswordAttribute extends RadiusAttribute {
    /**
     * 
     * @param identifierAndChapEncryptedPassword
     * @throws InvalidParameterException
     */
    public ChapPasswordAttribute(final byte[] identifierAndChapEncryptedPassword) throws InvalidParameterException{
        super(RadiusAttributeValues.CHAP_PASSWORD, identifierAndChapEncryptedPassword);
    }
    /**
     * 
     * @param identifier
     * @param chapEncryptedPassword
     * @throws InvalidParameterException
     */
    public ChapPasswordAttribute(final byte identifier, final byte[] chapEncryptedPassword) throws InvalidParameterException{
        byte[] identifierAndChapEncryptedPassword = new byte[1+chapEncryptedPassword.length];
        identifierAndChapEncryptedPassword[0] = identifier;
        System.arraycopy(identifierAndChapEncryptedPassword, 0, attributeBytes, 1, identifierAndChapEncryptedPassword.length);
        this( identifierAndChapEncryptedPassword);
    }

}
