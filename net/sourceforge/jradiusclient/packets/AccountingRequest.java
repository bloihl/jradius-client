package net.sourceforge.jradiusclient.packets;

import net.sourceforge.jradiusclient.attributes.AcctSessionIdAttribute;
import net.sourceforge.jradiusclient.attributes.AcctStatusTypeAttribute;
import net.sourceforge.jradiusclient.attributes.ServiceTypeAttribute;
import net.sourceforge.jradiusclient.attributes.UserNameAttribute;
import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.3 $
 */
public class AccountingRequest extends RadiusPacket {
    public final static byte[] START_ACCOUNTING_SERVICE_TYPE = new byte[]{0,0,0,1};
    public final static byte[] STOP_ACCOUNTING_SERVICE_TYPE = new byte[]{0,0,0,2};
    public final static byte[] UPDATE_ACCOUNTING_SERVICE_TYPE = new byte[]{0,0,0,3};
    public final static byte[] ENABLE_ACCOUNTING_SERVICE_TYPE = new byte[]{0,0,0,7};
    public final static byte[] DISABLE_ACCOUNTING_SERVICE_TYPE = new byte[]{0,0,0,8};
    private boolean initialized = false;
    /**
     * construct an account request packet for this session
     * @param userName
     * @param serviceType
     * @throws InvalidParameterException
     */
    public AccountingRequest(final String userName, final byte[] serviceType, final String sessionId )
            throws InvalidParameterException{
        super(RadiusPacket.ACCOUNTING_REQUEST);
        setAttribute(new UserNameAttribute(userName));
        setAttribute(new ServiceTypeAttribute(serviceType));
        setAttribute(new AcctStatusTypeAttribute(serviceType));
        setAttribute(new AcctSessionIdAttribute(sessionId.getBytes()));
        this.initialized = true;
    }
    /**
     * This method implements a callback from the super class RadiusPacket to validate input
     * @param radiusAttribute the attribute to validate
     * @throws InvalidParameterException if the RadiusAttribute does not pass validation
     */
    public void validateAttribute(final RadiusAttribute radiusAttribute) throws InvalidParameterException{
        if ((initialized) && (radiusAttribute.getType() == RadiusAttributeValues.USER_NAME ||
                    radiusAttribute.getType() == RadiusAttributeValues.SERVICE_TYPE ||
                    radiusAttribute.getType() == RadiusAttributeValues.ACCT_STATUS_TYPE ||
                    radiusAttribute.getType() == RadiusAttributeValues.ACCT_SESSION_ID  )){
            throw new InvalidParameterException ("Already initialized, cannot reset USER_NAME, SERVICE_TYPE, ACCT_STATUS_TYPE or ACCT_SESSION_ID.");
        }else if ((radiusAttribute.getType() == RadiusAttributeValues.SERVICE_TYPE) &&
                    (radiusAttribute.getValue().length != 4)){
            throw new InvalidParameterException ("SERVICE_TYPE must be 4 bytes long.");
        }
    }
}
