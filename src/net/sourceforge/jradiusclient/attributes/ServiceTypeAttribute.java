package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class ServiceTypeAttribute extends RadiusAttribute {
    /**
     * Constructs a new Attribute
     * @param serviceType
     * @throws InvalidParameterException
     */
    public ServiceTypeAttribute(final byte[] serviceType) throws InvalidParameterException{
        super(RadiusAttributeValues.SERVICE_TYPE, serviceType);
    }
}
