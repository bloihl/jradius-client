package net.sourceforge.jradiusclient.packets;

import net.sourceforge.jradiusclient.attributes.ServiceTypeAttribute;
import net.sourceforge.jradiusclient.attributes.UserNameAttribute;
import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class AccountingRequest extends RadiusPacket {
    private boolean initialized = false;
    public AccountingRequest(final String userName, final byte[] serviceType )
            throws InvalidParameterException{
        super(RadiusPacket.ACCOUNTING_REQUEST);
        setAttribute(new UserNameAttribute(userName));
        setAttribute(new ServiceTypeAttribute(serviceType));
        this.initialized = true;
    }
    /**
     * This method implements a callback from the super class RadiusPacket to validate input
     * @param radiusAttribute the attribute to validate
     * @throws InvalidParameterException if the RadiusAttribute does not pass validation
     */
    public void validateAttribute(final RadiusAttribute radiusAttribute) throws InvalidParameterException{
        if ((initialized) && (radiusAttribute.getType() == RadiusAttributeValues.USER_NAME ||
                    radiusAttribute.getType() == RadiusAttributeValues.SERVICE_TYPE )){
            throw new InvalidParameterException ("Already initialized, cannot reset username or ServiceType.");
        }
    }
}
