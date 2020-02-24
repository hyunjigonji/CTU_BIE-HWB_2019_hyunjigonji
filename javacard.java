/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package classicapplet1;
 
import javacard.framework.*;
import javacard.security.MessageDigest;
 
public class ClassicApplet1 extends Applet {
    byte[] array;
    byte[] name = {'l','h','j'};
    
    OwnerPIN pin;
    final static byte max_tries = 0x03;
    final static byte max_len = 0x08;
    
    MessageDigest MD;
    boolean correct = false;
    /**
 
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
 
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ClassicApplet1(bArray, bOffset);
    }
    /**
     * Only this class's install method should create the applet object.
     */
 
    protected ClassicApplet1(byte[] arr, short offset) {
        array = new byte[3];
        
        pin = new OwnerPIN(max_tries, max_len);
        short iLen = arr[(short)offset];
        short cLen = arr[(short)(offset+iLen+1)];
        short aLen = arr[(short)(offset+iLen+cLen+2)];
        pin.update(arr, (short)(offset+iLen+cLen+3), (byte)aLen);
        
        MD = MessageDigest.getInstance(MessageDigest.ALG_SHA, correct);
        
        register();
    }
 
    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
 
   public void process(APDU apdu) {
        //Insert your code here
        if(selectingApplet()) ISOException.throwIt(ISO7816.SW_NO_ERROR);
        
        byte [] buf = apdu.getBuffer();
        short len = 0;
        
        if(buf[ISO7816.OFFSET_CLA] != (byte)0x80) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        byte ins = buf[ISO7816.OFFSET_INS];
 
        switch(ins){
            case 0x00: //returns name - lhj
                len = apdu.setOutgoing();
                // if(len > name.length) ISOException.throwIt((short)(ISO7816.SW_CORRECT_LENGTH_00 + name.length));
                if (len > name.length) len = (short)name.length;
                apdu.setOutgoingLength(len);
                apdu.sendBytesLong(name, (short)0, len);
                break;
            case 0x01: //read data
                if(!pin.isValidated()) { // checking pin
                    ISOException.throwIt((short)0x6301);
                    break;
                }
                len = apdu.setIncomingAndReceive();
                if(len > 0x14) ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH));
                Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, array, (short)0, len);
                break;
            case 0x02: //write data
                if(!pin.isValidated()) { // checking pin
                    ISOException.throwIt((short)0x6301);
                    break;
                }
                len = apdu.setOutgoing();
                if(len != (short)array.length) ISOException.throwIt((short)(ISO7816.SW_CORRECT_LENGTH_00 + array.length));
                apdu.setOutgoingLength(len);
                apdu.sendBytesLong(array, (short)0, len);
                break;
            case 0x20: // pin
                if(pin.getTriesRemaining()==0) {
                    ISOException.throwIt((short)0x6300);
                    return;
                } // pin is blocked
                byte byteRead = (byte)(apdu.setIncomingAndReceive());
                correct = pin.check(buf, ISO7816.OFFSET_CDATA, byteRead);
                if(!correct){
                    ISOException.throwIt((short)0x6300); // verification failed
                }
                break;
            case 0x30: // accepts a byte sequence, returns SHA-1
                len = apdu.setIncomingAndReceive();
                if(len > 0x80) ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH));
                //Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, array, (short)0, len);
                
                MD.reset();
                //MD.doFinal(array, (short)0, len, array, (short)0);
                MD.doFinal(buf, ISO7816.OFFSET_CDATA, len, buf, ISO7816.OFFSET_CDATA);
                
                len = apdu.setOutgoing();
                apdu.setOutgoingLength(len);
                //apdu.sendBytesLong(array, (short)0, len);
                apdu.sendBytesLong(buf, ISO7816.OFFSET_CDATA, len);
                break;
            case 0x32: // returns SHA-1 of my name
                len = (short)name.length;
                //len = apdu.setOutgoing();
                
                MD.reset();
                //MD.doFinal(name, (short)0, len, name, (short)0);
                MD.doFinal(name, (short)0, len, buf, ISO7816.OFFSET_CDATA);
                
                len = apdu.setOutgoing();
                apdu.setOutgoingLength(len);
                apdu.sendBytesLong(buf, ISO7816.OFFSET_CDATA, len);
                
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
}
