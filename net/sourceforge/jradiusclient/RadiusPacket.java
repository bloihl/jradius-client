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
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.6 $
 */
public class RadiusPacket {
    public static final int MIN_PACKET_LENGTH       = 20;
    public static final int MAX_PACKET_LENGTH       = 4096;
    /**
     *RADIUS_HEADER_LENGTH is 20 bytes (corresponding to
     *1 byte for code + 1 byte for Identifier + 2 bytes for Length + 16 bytes for Request Authenticator)
     *It is not a coincidence that it is the same as the MIN_PACKET_LENGTH
     **/
    public static final short RADIUS_HEADER_LENGTH  = 20;
    public static final String EMPTYSTRING = "";

    /* ***************  Constant Packet Type Codes  **************************/
    public static final int ACCESS_REQUEST      = 1;
    public static final int ACCESS_ACCEPT       = 2;
    public static final int ACCESS_REJECT       = 3;
    public static final int ACCOUNTING_REQUEST  = 4;
    public static final int ACCOUNTING_RESPONSE = 5;
    public static final int ACCOUNTING_STATUS   = 6;
    public static final int PASSWORD_REQUEST    = 7;
    public static final int PASSWORD_ACCEPT     = 8;
    public static final int PASSWORD_REJECT     = 9;
    public static final int ACCOUNTING_MESSAGE  = 10;
    public static final int ACCESS_CHALLENGE    = 11;
    public static final int STATUS_SERVER       = 12;   // experimental
    public static final int STATUS_CLIENT       = 13;   // experimental
    public static final int RESERVED            = 255;
    /* ******************  Constant Packet Type Codes  *************************/
    private static Object nextPacketIdLock = new Object();
    private static byte nextPacketId = (byte)0;
    
    private int packetType = 0;
    private byte packetIdentifier = (byte)0;
    private Map attributes;
    /**
     * builds a type RadiusPacket with no Attributes set
     * @param type int a PacketType to send.
     * @throws InvalidParameterException if the attributeList is null or contains non-RadiusAttribute type entries
     */
    public RadiusPacket(final int type) throws InvalidParameterException{
        if((type < 1)||(type > 256)){
            throw new InvalidParameterException("Type was out of bounds");
        }
        this.packetType = type;
        this.packetIdentifier = getAndIncrementPacketIdentifier();
        this.attributes = new HashMap();
    }
    /**
     * Builds a RadiusPacket with a predefined set of attributes
     * @param type int a PacketType to send.
     * @param attributeList a list of RadiusAttribute objects to initialize this RadiusPacket with
     * @throws InvalidParameterException if the attributeList is null or contains non-RadiusAttribute type entries
     */
    public RadiusPacket(final int type, final List attributeList) throws InvalidParameterException{
        this(type);
        if((null == attributeList)||(attributeList.size() == 0)){
            throw new InvalidParameterException("Attribute List was null");
        }
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
            synchronized(this.attributes){
                this.attributes.put(new Integer(tempRa.getType()),tempRa);
            }
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
     * get the packet type for this RadiusPacket
     * @return packet type for this RadiusPacket
     */
    public byte getPacketType(){
        return (byte)this.packetType;
    }
    /**
     * Return the packetIdentifier for this RadiusPacket. This can be used to match request packets 
     * to response packets
     * @return the packet identifier for this object.
     */
    public byte getPacketIdentifier(){
        return this.packetIdentifier;
    }
    /**
     * get the byte array 
     * @return a byte array of the raw bytes for all of the RadiusAttributes assigned to this RadiusPacket
     * @throws RadiusException If there is any error assembling the bytes into a byte array
     */    
    protected final byte[] getAttributeBytes() throws RadiusException{
        //check for an empty packet
        ByteArrayOutputStream bytes = new  ByteArrayOutputStream();
        synchronized (this.attributes){
            Iterator attributeList = this.attributes.values().iterator();
            while(attributeList.hasNext()){
                try{
                    bytes.write(((RadiusAttribute)attributeList.next()).getBytes());
                }catch(java.io.IOException ioex){
                    throw new RadiusException ("Error writing bytes to ByteArrayOutputStream!!!");
                }
            }
            return bytes.toByteArray();
        }
    }
    /**
     * retrieves the next PacketIdentifier to use and increments the static storage
     * @return the next packetIdentifier to use.
     */
    private static byte getAndIncrementPacketIdentifier(){
        synchronized (nextPacketIdLock){
            return nextPacketId++;
        }
    }
}