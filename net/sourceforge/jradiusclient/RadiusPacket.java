package net.sourceforge.jradiusclient;

import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.exception.RadiusException;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
/**
 * <p>Released under the LGPL</p>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */

public class RadiusPacket {
    private Map attributes;
    public RadiusPacket(){
        //most packets will be at least 4 attributes
        this.attributes = new HashMap();
    }
    public RadiusPacket(List attributeList) throws InvalidParameterException{
        if((null == attributeList)||(attributeList.size() == 0)){
            throw new InvalidParameterException("Attribute List was null");
        }
        this.attributes = new HashMap(attributeList.size());
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
    public void setAttribute(RadiusAttribute ra) throws InvalidParameterException{
        if (null == ra){
            throw new InvalidParameterException("radiusAttribute was null");
        }
        synchronized(this.attributes){
            this.attributes.put(new Integer(ra.getType()),ra);
        }
    }
    public RadiusAttribute getAttribute(int attributeType) throws RadiusException{
        if ((attributeType < 0) || (attributeType > 256)){
            throw new RadiusException("attributeType is out of bounds");
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
    byte[] getPacketBytes() throws RadiusException{
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