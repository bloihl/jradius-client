package net.sourceforge.jradiusclient.attributes;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class ChapChallengeAttribute extends RadiusAttribute {
    /**
     * 
     * @param challenge
     * @throws InvalidParameterException
     */
    public ChapChallengeAttribute(final byte[] challenge) throws InvalidParameterException{
        super(RadiusAttributeValues.CHAP_CHALLENGE, challenge);
    }
    /**
     * 
     * @param challenge
     * @throws InvalidParameterException
     */
    public ChapChallengeAttribute(final String challenge) throws InvalidParameterException{
        this(challenge.getBytes());
    }

}
