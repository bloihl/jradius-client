package net.sourceforge.jradiusclient.packets;

import net.sourceforge.jradiusclient.attributes.UserNameAttribute;
import net.sourceforge.jradiusclient.attributes.UserPasswordAttribute;
import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.2 $
 */

public class PapRadiusPacket extends RadiusPacket {
    private boolean initialized = false;
    public PapRadiusPacket(final String userName, final String plaintextPassword )
            throws InvalidParameterException{
        this(userName,plaintextPassword.getBytes());
    }
    public PapRadiusPacket(final String userName, final byte[] plaintextPassword )
            throws InvalidParameterException{
        super (ACCESS_REQUEST);
        setAttribute(new UserNameAttribute(userName));
        setAttribute(new UserPasswordAttribute(plaintextPassword));
        this.initialized = true;
    }
    public void validateAttribute(RadiusAttribute ra) throws InvalidParameterException{
        if ((initialized) && (ra.getType() == RadiusAttribute.USER_NAME ||
                              ra.getType() == RadiusAttribute.USER_PASSWORD)){
            throw new InvalidParameterException ("Already initialized, cannot reset username or password.");
        }
    }
}