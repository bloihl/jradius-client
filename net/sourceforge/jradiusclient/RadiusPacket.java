package net.sourceforge.jradiusclient;

import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.exception.RadiusException;

import java.io.ByteArrayOutputStream;
import java.util.Collection;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
/**
 * <p>Released under the LGPL</p>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.2 $
 */
public class RadiusPacket {
    private Map attributes;
    /**
     * builds a RadiusPacket with no Attributes set
     */
    public RadiusPacket(){
        //most packets will be at least 4 attributes
        this.attributes = new HashMap();
    }
    /**
     * Builds a RadiusPacket with a predefined set of attributes
     * @param attributeList a list of RadiusAttribute objects to initialize this RadiusPacket with
     * @throws InvalidParameterException if the attributeList is null or contains non-RadiusAttribute type entries
     */
    public RadiusPacket(List attributeList) throws InvalidParameterException{
        if((null == attributeList)||(attributeList.size() == 0)){
            throw new InvalidParameterException("Attribute List was null");
        }
        this.attributes = new HashMap(attributeList.size());
        this.setAttributes(attributeList);
    }
    /**
     * Adds a RadiusAttribute to this RadiusPacket
     * @param radiusAttribute A RadiusAttribute to set on this RadiusPacket
     * @throws InvalidParameterException if the parameter radiusAttribute was null
     */
    public void setAttribute(RadiusAttribute radiusAttribute) throws InvalidParameterException{
        if (null == radiusAttribute){
            throw new InvalidParameterException("radiusAttribute was null");
        }
        synchronized(this.attributes){
            this.attributes.put(new Integer(radiusAttribute.getType()),radiusAttribute);
        }
    }
    /**
     * Add a set of RadiusAttributes to this RadiusPacket
     * @param attributeList a list of RadiusAttribute objects to add to this RadiusPacket
     * @throws InvalidParameterException if the attributeList is null or contains non-RadiusAttribute type entries
     */
    public void setAttributes(List attributeList) throws InvalidParameterException{
        if((null == attributeList)||(attributeList.size() == 0)){
            throw new InvalidParameterException("Attribute List was null");
        }
        RadiusAttribute tempRa;
        Iterator iter = attributeList.iterator();
        while(iter.hasNext()){
            try{
                tempRa = (RadiusAttribute)iter.next();
            }catch(ClassCastException ccex){
                throw new InvalidParameterException("Attribute List contained an entry that was not a net.sourceforge.jradiusclient.RadiusAttribute");
            }
            this.attributes.put(new Integer(tempRa.getType()),tempRa);
        }
    }
    /**
     * retrieve a RadiusAttribute from this RadiusPacket
     * @param attributeType an integer between 0 and 256 (i.e. a byte) from the list of Radius constants in 
     * net.sourceforge.jradiusclient.RadiusValues
     * @return a single RadiusAttribute from the RadiusPacket
     * @throws RadiusException if no attribute of type attributeType is stored in this RadiusPacket
     * @throws InvalidParameterException if the attributeType is not between 0 and 256 (i.e. a byte)
     */
    public RadiusAttribute getAttribute(int attributeType) throws InvalidParameterException,RadiusException{
        if ((attributeType < 0) || (attributeType > 256)){
            throw new InvalidParameterException("attributeType is out of bounds");
        }
        RadiusAttribute tempRa = null;
        synchronized(this.attributes){
            tempRa = (RadiusAttribute)this.attributes.get(new Integer(attributeType));
        }
        if (null == tempRa){
            throw new RadiusException("No attribute found for type " +  attributeType);
        }
        return tempRa;
    }
    /**
     * get all of the RadiusAttributes in this RadiusPacket
     * @return a java.util.Collection of RadiusAttributes
     */
    public Collection getAttributes(){
        //I am concerned about handing out a Collection that is backed by the attributes map, 
        //i.e. changes to our own internal provate data can happen this way!!!!
        return this.attributes.values();
    }
    /**
     * get the byte array 
     * @return a byte array of the raw bytes for all of the RadiusAttributes assigned to this RadiusPacket
     * @throws RadiusException If there is any error assembling the bytes into a byte array
     */    
    protected final byte[] getPacketBytes() throws RadiusException{
        //check for an empty packet
        ByteArrayOutputStream bytes = new  ByteArrayOutputStream();
        synchronized (this.attributes){
            Iterator attributeList = this.attributes.values().iterator();
            while(attributeList.hasNext()){
                try{
                    bytes.write(((RadiusAttribute)attributeList.next()).getPacketBytes());
                }catch(java.io.IOException ioex){
                    throw new RadiusException ("Error writing bytes to ByteArrayOutputStream!!!");
                }
            }
            return bytes.toByteArray();
        }
    }
}