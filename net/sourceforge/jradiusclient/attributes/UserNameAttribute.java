package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */

public class UserNameAttribute extends RadiusAttribute {

    public UserNameAttribute(final String username) throws InvalidParameterException {
        super(RadiusAttributeValues.USER_NAME,username.getBytes());
    }
    public String getUserName(){
        return new String(getValue());
    }
}