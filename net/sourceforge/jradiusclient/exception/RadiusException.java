package net.sourceforge.jradiusclient.exception;

import java.lang.Exception;
/**
 *
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */

public class RadiusException extends Exception{
    /**
     * @param message the exception message
     */
    public RadiusException(String message){
        super(message);
    }
}
