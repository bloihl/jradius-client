package net.sourceforge.jradiusclient;

import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
/**
 * <p>Released under the LGPL</p>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class RadiusAttribute implements RadiusValues{
    private static final int HEADER_LENGTH = 2;
    private byte[] packetBytes;
// This implementation is oriented towards slow construction but fast retrieval
// of the bytes at send time.
    public RadiusAttribute(final int type, final byte[] value) throws InvalidParameterException {
        if (type > 256)  {
            throw new InvalidParameterException("type must be small enough to fit in a byte (i.e. less than 256) and should be chosen from static final constants defined in RadiusValues");
        }else if(null == value){
            throw new InvalidParameterException("Value cannot be NULL");
        }
        int length = HEADER_LENGTH + value.length;// 2 byte header
        ByteArrayOutputStream temp = new ByteArrayOutputStream(length);
        try{
            temp.write(type);
            temp.write(length);
            temp.write(value);
            temp.flush();
        }catch(IOException ioex){//this should never happen
            throw new InvalidParameterException("Error constructing RadiusAttribute");
        }
        this.packetBytes = temp.toByteArray();
        //we don't want to abort the constructor if we fail to close temp
        try{temp.close();}catch(IOException ignore){}
    }
    public int getType(){
        return this.packetBytes[0];
    }
    public byte[] getValue(){
        int valueLength = this.packetBytes.length - HEADER_LENGTH;
        byte [] valueBytes = new byte[valueLength];
        System.arraycopy(this.packetBytes,2,valueBytes,0,valueLength);
        return valueBytes;
    }
    public byte[] getPacketBytes(){
        return this.packetBytes;
    }
}
