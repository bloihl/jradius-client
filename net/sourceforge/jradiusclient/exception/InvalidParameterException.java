package net.sourceforge.jradiusclient.exception;

import java.lang.Exception;
/**
 *
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */

public class InvalidParameterException extends Exception{
    /**
     * The default message constructor
     */
    public InvalidParameterException(){
        this("An Invalid Parameter was sent to this method!");
    }
    /**
     * Constructs an InvalidParameterException with the specified message
     * @param message the exception message
     */
    public InvalidParameterException(String message){
        super(message);
    }
}
