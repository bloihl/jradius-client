package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.3 $
 */

public class UserNameAttribute extends RadiusAttribute {
    /**
     * Constructs a new UserNameAttribute for use in RadiusPackets
     * @param username java.lang.String
     * @throws InvalidParameterException
     */
    public UserNameAttribute(final String username) throws InvalidParameterException {
        super(RadiusAttributeValues.USER_NAME,username.getBytes());
    }
    /**
     * gets the username stored in this object
     * @return java.lang.String the user name stored in this attribute
     */
    public String getUserName(){
        return new String(getValue());
    }
}