package applet;

import applet.SimpleEMVApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javacard.framework.JCSystem;
import javax.xml.bind.DatatypeConverter;



/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class SimpleAPDU {
    private static String APPLET_AID = "73696d706c656170706c6574";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    private  RSAkeygen r = new RSAkeygen();
    private byte pkey [] = { 
         (byte) 0x01, (byte) 0x02, (byte) 0x03
    };
   

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            SimpleAPDU main = new SimpleAPDU();
         //main.setCertificate();
         main.POS_Get_Card_Certificate();       
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void setCertificate() throws Exception {
    
        
        byte []responsedata = new byte[128];
        byte []sig = new byte[128];
        byte []sig1 = new byte[128];
        byte []hashpub = new byte[32]; 
        byte []temp = null; 
        temp = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        //CommandAPDU cmdAPDU = null;
        
        
        demoGetRandomDataCommand(responsedata,new CommandAPDU(0x00,0xD0,0x00,0x00));
        System.out.println("response :" + responsedata);
   
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        hashpub =sha256.digest(responsedata);
        System.out.println(" hashpubkeymodn dhjdks = "+ Arrays.toString(hashpub));
        System.out.println("Hash "+DatatypeConverter.printHexBinary(hashpub));
       
        
        System.arraycopy(hashpub, 0, temp, 0, 32);
        r.setciphertext(temp, (short)0,(short)temp.length );
       
        System.out.println("temp" + DatatypeConverter.printHexBinary(temp));
        
        r.decrypt();
        r.getplaintext(sig, (short)0, (short)128);
        //r.setdata(sig, (short)0, (short)128);
        //r.encrypt();
        //r.getciphertext(sig1, (short)0, (short)128);
        
        System.out.println("Sig" + DatatypeConverter.printHexBinary(sig));
        // System.out.println("Sig" + DatatypeConverter.printHexBinary(sig));
          //System.out.println("hashDatatypeConverter.printHexBinary(hashpub));
       demoGetRandomDataCommand(responsedata,new CommandAPDU(0x00,0xD1,0x00,0x00,sig)); // only tests whethersame data signature ois returned
        
        
    }
    public void demoGetRandomDataCommand(byte[] responsedata, CommandAPDU cmdAPDU) throws Exception {
                
        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);  
       
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // A) If running on physical card
        runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator 
        //runCfg.setAppletToSimulate(SimpleApplet.class); // main class of applet to simulate
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        // Transmit single APDU
         ResponseAPDU response = cardMngr.transmit(cmdAPDU);
         System.arraycopy(response.getBytes(), 0, responsedata, 0, 128);
         cardMngr.Disconnect(true);
        
    }

    public void POS_Get_Card_Certificate() throws Exception {
        
        RSACard cardrsa = new RSACard();
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card
         byte []temp = null; 
        temp = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        //runCfg.setAppletToSimulate(SimpleApplet.class); 
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00,0xD2,0x11,0x11));
        System.out.println("Response D2:" + DatatypeConverter.printHexBinary( response.getData()));
        
       if(cardVerify(response.getData()))
       { byte []temp1 = null; 
         temp1 = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
           System.out.println("Signature Verified");
           
           System.out.println("INPUT PIN");
           byte [] PIN = {(byte)0x12, (byte) 0x34};
           
           System.arraycopy(response.getData(), 0, temp, 0, (short)128);  // reads modulus received from card
           cardrsa.setModulus(response.getData(), (short)0, (short)128); 
          
           System.arraycopy(PIN, 0, temp1, 0, (short)2); 
           cardrsa.setdata(temp1, (short)0,(short) 2);
           cardrsa.encrypt();
           cardrsa.getciphertext(temp, (short)0, (short)128);
            
           response = cardMngr.transmit(new CommandAPDU(0x00,0x20,0x00,0x88,temp));
           System.out.println("response verify PIN:" + DatatypeConverter.printHexBinary( response.getData()));
           
       }
       else 
           System.out.println("Signature Not Verified");
    }    
    
    public boolean cardVerify(byte[] response ) throws Exception {
        
        //byte []card_exponent = new byte[3];
         byte []card_modulus = new byte[128];
         byte []card_signature = new byte[128]; 
         byte []decrypted_hash = new byte[128]; 
         byte []calculated_hash = new byte[128]; 
         
         byte []temp = null; 
         temp = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        
        
        // System.arraycopy(response, 0, card_exponent, 0, (short)3);
        System.arraycopy(response, 0, card_modulus, 0, (short)128); 
        System.arraycopy(response, 128, card_signature, 0, (short)128);
        System.arraycopy(card_signature, 0, temp, 0, 128);
        r.setdata(temp, (short)0,(short)temp.length );
        
        r.encrypt();
        r.getciphertext(decrypted_hash, (short)0, (short)128);
        
        // now compare decrypted_hash with hash of modulus
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        calculated_hash =sha256.digest(card_modulus);
        System.out.println("Calculated Hash " + DatatypeConverter.printHexBinary(calculated_hash));
        System.out.println("DEcrypeted HAsh " + DatatypeConverter.printHexBinary(decrypted_hash));
        return(CompareHash(calculated_hash,decrypted_hash,32));
      
    }    
    public boolean CompareHash(byte [] calculated_hash, byte [] decrypted_hash,int length ) throws Exception {
        
     
        
        for(int i=0;i<32;i++)
        {
            if(calculated_hash[i] != decrypted_hash[i])
                return false;
        }
        return true;
    }
}
