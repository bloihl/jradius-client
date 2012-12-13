package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class EapMessageAttribute extends RadiusAttribute {
    /**
     * Constructs an attribute using the provided EAP Message bytes
     * @param eapMessage
     * @throws InvalidParameterException
     */
    public EapMessageAttribute(final byte[] eapMessage) throws InvalidParameterException{
        super(RadiusAttributeValues.EAP_MESSAGE, eapMessage);
    }
}
