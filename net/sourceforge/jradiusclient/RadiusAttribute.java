package net.sourceforge.jradiusclient;

import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.6 $
 */
public class RadiusAttribute implements RadiusAttributeValues{
    private static final int HEADER_LENGTH = 2;
    private byte[] packetBytes;
    /**
     * Construct a basic RadiusAttribute
     * @throws InvalidParameterException if the type is not a valid Radius Attribute Type see RFCs 2865 and 2866
     */
    public RadiusAttribute(final int type, final byte[] value) throws InvalidParameterException {
        if (type > 256)  {
            throw new InvalidParameterException("type must be small enough to fit in a byte (i.e. less than 256) and should be chosen from static final constants defined in RadiusValues");
        }else if(null == value){
            throw new InvalidParameterException("Value cannot be NULL");
        }

        //  This implementation is oriented towards slow construction but fast retrieval
        //  of the bytes at send time.
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
    /**
     * get the Radius Type for this Attribute( see rfc 2865 and 2866)
     * @return the Radius Type for this Attribute
     */
    public int getType(){
        return this.packetBytes[0];
    }
    /**
     * get the data stored for this RadiusAttribute
     * @return the byte[] stored as the value for this RadiusAttribute
     */
    public byte[] getValue(){
        int valueLength = this.packetBytes.length - HEADER_LENGTH;
        byte [] valueBytes = new byte[valueLength];
        System.arraycopy(this.packetBytes,2,valueBytes,0,valueLength);
        return valueBytes;
    }
    /**
     * get the bytes that will go into a RadiusPacket
     * @return the byte array to be used in construction of a RadiusPacket
     */
    protected final byte[] getBytes(){
        return this.packetBytes;
    }
//  /**
//   * This method is used to set a byte array attribute in the Request Attributes
//   * portion of the packet. Use one of the other two methods to set simple attributes.
//   * This method should only be called directly to set a password attribute,
//   * where the length expected by the radius server is the actual length of the
//   * password not the length of the MD5 encrypted byte array (16 bytes) that go
//   * into the packet.
//   * @param type int attribute type
//   * @param length int length of attribute, this is normally the length of the byte array
//   *                   but in the case of the password attribute it is the actual length
//   *                   of the password not the length of the MD5 hashed 16 byte value actually
//   *                   passed to the radius server
//   * @param attribute byte[] the actual attribute byte array
//   * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
//   */
//  private void setAttribute(int type, int length, byte [] attribute, ByteArrayOutputStream requestAttributes) {
//      //1 byte: Type
//      requestAttributes.write(type);
//
//      //1 byte: length of the Type plus 2 bytes for the rest of this attirbute.
//      requestAttributes.write(length + 2);
//
//      //Value.length() bytes: the actual Value.
//      requestAttributes.write(attribute, 0, length);
//  }
//  /**
//   * This method is used to set a byte array attribute in a Request Attributes
//   * ByteArrayOutputStream that can be passed in to the authenticate method.
//   * Things that CANNOT/SHOULD NOT be set here are the
//   * <UL><LI>RadiusClient.USER_NAME</LI>
//   *     <LI>RadiusClient.USER_PASSWORD </LI>
//   *     <LI>RadiusClient.NAS_IDENTIFIER </LI>
//   *     <LI>RadiusClient.STATE </LI>
//   * </UL>
//   * If you attempt to set one you will get an InvalidParameterException
//   * @param type int attribute type
//   * @param attribute byte[] the actual attribute byte array
//   * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
//   * @throws InvalidParameterException
//   */
//  public void setUserAttribute(int type, byte [] attribute, ByteArrayOutputStream requestAttributes)
//  throws InvalidParameterException {
//      //check to make sure type is not one we will set in authenticate method
//      if (type == RadiusAttributeValues.USER_NAME) {
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.USER_NAME");
//      }else if (type == RadiusAttributeValues.USER_PASSWORD) {
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.USER_PASSWORD");
//      }else if (type == RadiusAttributeValues.NAS_IDENTIFIER) {
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.NAS_IDENTIFIER");
//      }else if (type == RadiusAttributeValues.STATE){
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.STATE");
//      }
//      this.setAttribute(type, attribute.length, attribute, requestAttributes);
//  }
//  /**
//   * This method is used to set a byte array attribute in a Request Attributes
//   * ByteArrayOutputStream that can be passed in to the authenticate method.
//   * Things that CANNOT/SHOULD NOT be set here are the
//   * <UL><LI>RadiusClient.USER_NAME</LI>
//   *     <LI>RadiusClient.USER_PASSWORD </LI>
//   *     <LI>RadiusClient.NAS_IDENTIFIER </LI>
//   *     <LI>RadiusClient.STATE </LI>
//   * </UL>
//   * If you attempt to set one you will get an InvalidParameterException
//   * @param type int attribute type
//   * @param subType int sub attribute type
//   * @param attribute byte[] the actual attribute byte array
//   * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
//   * @throws InvalidParameterException
//   * author kay michael koehler koehler@remwave.com, koehler@buddy4mac.com, koehler@econo.de
//   */
//  public void setUserSubAttribute(int type, int subType, byte [] attribute, ByteArrayOutputStream requestAttributes)
//  throws InvalidParameterException {
//      if (type == RadiusAttributeValues.USER_NAME) {
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.USER_NAME");
//      }else if (type == RadiusAttributeValues.USER_PASSWORD) {
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.USER_PASSWORD");
//      }else if (type == RadiusAttributeValues.NAS_IDENTIFIER) {
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.NAS_IDENTIFIER");
//      }else if (type == RadiusAttributeValues.STATE){
//          throw new InvalidParameterException("Cannot set attribute to one of type RadiusClient.STATE");
//      }
//      //1 byte: Type
//      requestAttributes.write(type);
//
//      //1 byte: length of the Type plus 4 bytes for the rest of this attribute (total of >=5 bytes)
//      requestAttributes.write(attribute.length + 4);
//
//      requestAttributes.write(subType);
//
//      //1 byte: length of the attribute plus 2 bytes for minimal length (total of >=3 bytes)
//      requestAttributes.write(attribute.length + 2);
//
//      //Value.length() bytes: the actual Value.
//      requestAttributes.write(attribute, 0, attribute.length);
//  }
//  /**
//   * This method is used to set a byte array attribute in the Request Attributes
//   * portion of the packet.
//   * @param type int attribute type
//   * @param attribute byte[] the actual attribute byte array
//   * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
//   */
//  private void setAttribute(int type, byte [] attribute, ByteArrayOutputStream requestAttributes) {
//      this.setAttribute(type, attribute.length, attribute, requestAttributes);
//  }
//  /**
//   * This method is used to set a single byte attribute in the Request Attributes
//   * portion of the packet.
//   * @param type int attribute type
//   * @param attribute byte the actual attribute byte
//   * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
//   */
//  private void setAttribute(int type, byte attribute, ByteArrayOutputStream requestAttributes) {
//      byte [] attributeArray = {attribute};
//      this.setAttribute(type, attributeArray.length, attributeArray, requestAttributes);
//  }
//    /**
//     *
//     */
//    private Integer attributeBytesToInteger(byte[] input){
//        int value = 0, tmp =0;
//        for(int i = 0; i<input.length;i++){
//            tmp = input[i] & 0x7F;
//            if((input[i]&80000000) != 0){
//                tmp |=0x80;
//            }
//            value = (256 * value) + tmp;
//        }
//        return new Integer(value);
//    }
//    /**
//     *
//     */
//    private String attributeBytesToIPAddr(byte[] input)throws RadiusException{
//        if (input.length > 4){
//            throw new RadiusException("Invalid IP Address - too many bytes");
//        }
//        StringBuffer ipaddr = new StringBuffer();
//        for(int i =0; i<4;i++){
//            if((input[i]&80000000)!=0){
//                ipaddr.append((input[i] & 0x7F) | 0x80);
//            }else{
//                ipaddr.append((input[i] & 0x7F));
//            }
//            if (i != 3){
//                ipaddr.append(".");
//            }
//        }
//        return ipaddr.toString();
//    }
}
