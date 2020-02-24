/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
 
package cardcomm;
 
/*
 * Main.java
 *
 * Created on 5. únor 2008, 11:02
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */
 
import java.util.*;
import javax.smartcardio.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException; 
/**
 *
 * @author bucekj
 */
public class Main {
    /** Creates a new instance of Main */
    public Main() {
    }
    CardChannel cardChannel;
    /**
     * @param args the command line arguments
     */    
    public static void main(String[] args) {
 
        
        // get the list of available terminals
        try {
            MessageDigest MD = MessageDigest.getInstance("SHA-1");
            byte[] array = new byte[3];
            byte[] name = {'l','h','j'};
            byte[] newhash = new byte[20];
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            System.out.println("Terminals: " + terminals);
            // get the first terminal
            CardTerminal terminal = null;
            for (CardTerminal t : terminals) {
                if (t.isCardPresent()) {
                    terminal = t;
                    break;
                }
            }
            if (terminal == null) {
                System.err.println("Neni karticka!");
                throw new Exception("Neni karticka");
            }
            // establish a connection with the card
            Card card = terminal.connect("T=1");
            System.out.println("card: " + card);
            System.out.print("ATR: ");
            byte[]bb=card.getATR().getBytes();
            for (byte b : bb) {
                System.out.printf("%02x", ((int)b)&0xff);
            }
            System.out.println();
            CardChannel channel = card.getBasicChannel();
 
            CommandAPDU c;
            ResponseAPDU r;
 
            c = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09}); // select
            r = channel.transmit(c);
                    
            byte[] rb = r.getBytes();
            System.out.printf("select: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println(); 
            //*/
            c = new CommandAPDU(0x80, 0x20, 0x00, 0x00, new byte[]{0x12, 0x34, 0x56, 0x77}); // wrong pin
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("wrong pin: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println();
            //*/
            c = new CommandAPDU(0x80, 0x20, 0x00, 0x00, new byte[]{0x12, 0x34, 0x56, 0x77}); // wrong pin
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("wrong pin: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println();
            //*/
            c = new CommandAPDU(0x80, 0x20, 0x00, 0x00, new byte[]{0x12, 0x34, 0x56, 0x78}); // correct pin
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("correct pin: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println();
            //*/
            c = new CommandAPDU(0x90, 0x00, 0x00, 0x00, 0x00); // correct pin
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("wrong cla: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println();
            //*/
            c = new CommandAPDU(0x80, 0x00, 0x00, 0x00, 0x03); // my name
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("return my name: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println();
           
            MD.update(name,(short)0,(short)3);
            array = MD.digest();
            
            //*/
            c = new CommandAPDU(0x80, 0x30, 0x00, 0x03, new byte[]{0x01, 0x02, 0x03, 0x14}); // make hash
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("make hash: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println();
            //*/
            c = new CommandAPDU(0x80, 0x32, 0x00, 0x00, 0x14); // hash of name
            r = channel.transmit(c);
            rb = r.getBytes();
            byte[] rc;
            rc = r.getData();
            System.out.printf("hash of my name: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            for(int i = 0 ; i < rb.length-2 ; i++){
                newhash[i]=rb[i];
            }
            System.out.println();
            
            if(MD.isEqual(array,rc)){
                System.out.println("correct Hash");
            }
            else System.out.println("wrong Hash");
            
            //*/
            c = new CommandAPDU(0x80, 0x01, 0x00, 0x03, new byte[]{0x0a, 0x0b, 0x0c}); // read data
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("accept data: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println(); 
            //*/
            c = new CommandAPDU(0x80, 0x02, 0x00, 0x00, 0x03); // write data
            r = channel.transmit(c);
            rb = r.getBytes();
            System.out.printf("sends back data: ");
            for (int i = 0; i < rb.length; i++) {
                System.out.printf("%02X", rb[i]);
            }
            System.out.println(); 
            //*/
 
            // disconnect
            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
 
    }
 
    public static byte [] hexToBytes(String hex) {
        byte[] r = new byte[hex.length()/2];
        int i;
        for (i = 0; i < hex.length(); i = i + 2) {
            r[i/2] = Byte.parseByte(hex.substring(i, i+1), 16);
        }
        return r;
    }
 
}

