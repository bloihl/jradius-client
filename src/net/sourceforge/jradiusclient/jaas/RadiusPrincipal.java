package net.sourceforge.jradiusclient.jaas;

import java.security.Principal;

/**
 *
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class RadiusPrincipal implements Principal{
    private String principalName;
    /**
     * Constructs RadiusPrincipal objects
     * @param name java.lang.String The name of this principal
     */
    public RadiusPrincipal(String name){
        if (name == null){
            throw new NullPointerException("Illegal name input, name cannot be null.");
        }
        this.principalName = name;
    }
    /**
     * Gets the name of this <code>RadiusPrincipal</code>
     * @return java.lang.String The name of this <code>RadiusPrincipal</code>
     */
    public String getName(){
        return this.principalName;
    }
    /**
     * This method returns a string representation of this
     * <code>RadiusPrincipal</code>.
     *
     * @return a string representation of this <code>RadiusPrincipal</code>.
     */
    public String toString(){
        return this.getName();
    }
    /**
     * Compares the specified Object with this <code>RadiusPrincipal</code>
     * for equality.  Returns true if the given object is also a
     * <code>RadiusPrincipal</code> and the two RadiusPrincipal
     * have the same username.
     * @param object Object to be compared for equality with this
     *		<code>RadiusPrincipal</code>.
     *
     * @return true if the specified Object is equal to this
     *		<code>RadiusPrincipal</code>.
     */
    public boolean equals(Object object){
        if (object == null){
            return false;
        }
        if (this == object){
            return true;
        }
        if (!(object instanceof RadiusPrincipal)){
            return false;
        }
        RadiusPrincipal that = (RadiusPrincipal)object;
        if (this.getName().equals(that.getName())){
            return true;
        }
        return true;
    }
    /**
     * @return int the hashCode for this <code>RadiusPrincipal</code>
     */
    public int hashCode(){
        return this.principalName.hashCode();
    }
}