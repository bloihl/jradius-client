package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class AcctStatusTypeAttribute extends RadiusAttribute {
    /**
     * 
     * @param serviceType
     * @throws InvalidParameterException
     */
    public AcctStatusTypeAttribute(final byte[] statusType) throws InvalidParameterException{
        super(RadiusAttributeValues.ACCT_STATUS_TYPE, statusType);
    }

}
