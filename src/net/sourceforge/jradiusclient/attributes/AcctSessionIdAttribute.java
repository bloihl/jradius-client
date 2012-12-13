package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class AcctSessionIdAttribute extends RadiusAttribute {
   /**
    * 
    * @param sessionId
    * @throws InvalidParameterException
    */
   public AcctSessionIdAttribute(final byte[] sessionId) throws InvalidParameterException{
       super(RadiusAttributeValues.ACCT_SESSION_ID, sessionId);
   }

}
