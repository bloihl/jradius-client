package net.sourceforge.jradiusclient.packets;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.attributes.ChapChallengeAttribute;
import net.sourceforge.jradiusclient.attributes.ChapPasswordAttribute;
import net.sourceforge.jradiusclient.attributes.UserNameAttribute;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.util.ChapUtil;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.4 $
 */
public class ChapAccessRequest extends RadiusPacket {
    private static final ChapUtil chapUtil = new ChapUtil();
    private boolean initialized = false;
    /**
     * 
     * @param userName
     * @param chapEncryptedPassword
     * @param chapIndentifier
     * @param chapChallenge
     * @throws InvalidParameterException
     */
    public ChapAccessRequest(final String userName, final byte[] chapEncryptedPassword, final byte chapIndentifier, final byte[] chapChallenge)
            throws InvalidParameterException{
        super (ACCESS_REQUEST);
        initialize(userName, chapEncryptedPassword, chapIndentifier, chapChallenge);
    }
    /**
     * 
     * @param userName
     * @param plaintextPassword
     * @throws InvalidParameterException
     */
    public ChapAccessRequest(final String userName, final String plaintextPassword )
            throws InvalidParameterException{
        this(userName, plaintextPassword.getBytes(), ChapUtil.DEFAULT_CHALLENGE_SIZE);
    }
    /**
     * 
     * @param userName
     * @param plaintextPassword
     * @throws InvalidParameterException
     */
    public ChapAccessRequest(final String userName, final byte[] plaintextPassword)
            throws InvalidParameterException{
        this(userName, plaintextPassword, ChapUtil.DEFAULT_CHALLENGE_SIZE);
    }
    /**
     * 
     * @param userName
     * @param plaintextPassword
     * @throws InvalidParameterException
     */
    public ChapAccessRequest(final String userName, final byte[] plaintextPassword, final int challengeSize)
            throws InvalidParameterException{
        super (ACCESS_REQUEST);
        byte chapIndentifier = chapUtil.getNextChapIdentifier();
        byte[] chapChallenge = chapUtil.getNextChapChallenge(challengeSize);
        byte[] chapEncryptedPassword = ChapUtil.chapEncrypt(chapIndentifier, plaintextPassword, chapChallenge);
        initialize(userName, chapEncryptedPassword, chapIndentifier, chapChallenge);
    }
    /**
     * 
     * @param userName
     * @param chapEncryptedPassword
     * @param chapIndentifier
     * @param chapChallenge
     * @throws InvalidParameterException
     */
    private void initialize(final String userName, final byte[] chapEncryptedPassword, final byte chapIndentifier, final byte[] chapChallenge)
    throws InvalidParameterException{
        setAttribute(new UserNameAttribute(userName));
        setAttribute(new ChapPasswordAttribute(chapIndentifier,chapEncryptedPassword));
        setAttribute(new ChapChallengeAttribute(chapChallenge));
        this.initialized = true;
    }
    /**
     * This method implements a callback from the super class RadiusPacket to validate input
     * @param radiusAttribute the attribute to validate
     * @throws InvalidParameterException if the RadiusAttribute does not pass validation
     */
    public void validateAttribute(final RadiusAttribute radiusAttribute) throws InvalidParameterException{
        if ((initialized) && (radiusAttribute.getType() == RadiusAttributeValues.USER_NAME ||
                    radiusAttribute.getType() == RadiusAttributeValues.CHAP_PASSWORD ||
                    radiusAttribute.getType() == RadiusAttributeValues.CHAP_CHALLENGE)){
            throw new InvalidParameterException ("Already initialized, cannot reset username, chap password or chap challenge.");
        }else if (radiusAttribute.getType() == RadiusAttributeValues.USER_PASSWORD){
            throw new InvalidParameterException ("Already initialized, cannot set USER_PASSWORD in a CHAP Access Request.");
        }
    }
}