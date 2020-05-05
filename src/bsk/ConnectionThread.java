/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk;

import java.awt.MouseInfo;
import java.awt.PointerInfo;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author Dawid
 */
public class ConnectionThread extends AbstractCipher implements Runnable 
{
    private Socket socket;
    private static int port = 50505;
    private String message;
    private String password = new String("");
    
    public void setPassword(String psw)
    {
        this.password = psw;
    }
    
    public String getMessage()
    {
        return message;
    }
    
    public void setMessage(String msg)
    {
        this.message = msg;
    }
    
    public void alertReceiveMessage(String msg)
    {
        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Otrzymałeś wiadomość: ");
        alert.setHeaderText(null);
        alert.setContentText(msg);
        alert.showAndWait();
    }
    
    public String decipherMsg(String encryptedMsg, String mode, SecretKey key)
    {
        String msg = "";
        switch(mode)
        {
           case FileJob.ECB:
                msg = doCipheringMsg(encryptedMsg, mode, FileJob.ECB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
           case FileJob.CBC:
                msg = doCipheringMsg(encryptedMsg, mode, FileJob.CBC_METHOD, Cipher.DECRYPT_MODE, key);
                break;
           case FileJob.CFB:
                msg = doCipheringMsg(encryptedMsg, mode, FileJob.CFB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
           case FileJob.OFB:
                msg = doCipheringMsg(encryptedMsg, mode, FileJob.OFB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
        }
        return msg;
    }   
    
    public byte[] decipherFile(byte[] output, String mode, SecretKey key)
    {
        //int i = job.getFile().getName().lastIndexOf(".");
        //String extension =job.getFile().getName().substring(i+1);
        //String pathName = job.getFile().getName()+"."+extension;
        //File output = new File(pathName);
        //String pathName2 =  "de"+job.getFile().getName()+"."+extension;
        //File outputDecrypted = new File(pathName2);
        byte result[] = null;
        switch (mode)
        {
            case FileJob.ECB:
               result = doCipheringFile(output, mode, FileJob.ECB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
            case FileJob.CBC:
                result = doCipheringFile(output, mode, FileJob.CBC_METHOD, Cipher.DECRYPT_MODE, key);
                break;
            case FileJob.CFB:
                result = doCipheringFile(output, mode, FileJob.CFB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
            case FileJob.OFB:
                 result = doCipheringFile(output, mode, FileJob.OFB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
        }
        //Platform.runLater(() -> job.setStatus(FileJob.STATUS_DONE));
        return result;
    }
    
    public PrivateKey loadPrivateKey()
    {
        try
        {
            Path privatePath = Paths.get(privateKeyPath);
            byte[] privateKeyBytes = Files.readAllBytes(privatePath);
            SecretKey secretKey = hashPassword(this.password);
            byte[] iv = { 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher decryptPrivateKey = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decryptPrivateKey.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            byte[] decryptedPrivateKey = decryptPrivateKey.doFinal(privateKeyBytes);
            
            PKCS8EncodedKeySpec pvtKs = new PKCS8EncodedKeySpec(decryptedPrivateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kf.generatePrivate(pvtKs);
            return pvt;
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        return null;
    }
   
     @Override 
    public void run()
    {
        try (ServerSocket server = new ServerSocket(port)) {
            while (true)
            {
                  socket = server.accept();
                  Platform.runLater(() -> {
                    String psw = createDialog();
                    setPassword(psw);
                  });
                  
                  while(this.password.equals(""))
                  {
                      System.out.print("");
                  }

                  DataInputStream dis = new DataInputStream(socket.getInputStream());
                  //BufferedReader reader = new BufferedReader(new InputStreamReader(dis));
                  //System.out.println(dis.available());
                  String[] recv = dis.readUTF().split("\n");
                  String mode = recv[0];
                  String s = recv[1];
                  
                  byte[] key = Base64.getDecoder().decode(s);         
                  String type = recv[2];
                  
                  PrivateKey pvt = loadPrivateKey();
                  Cipher cipherKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                  cipherKey.init(Cipher.DECRYPT_MODE, pvt);
                  byte [] decryptedByteKey =cipherKey.doFinal(key);
                  SecretKey secretKey = new SecretKeySpec(decryptedByteKey, "AES");
                  
                  if (type.equals("file"))
                  {              
                      String fileName = recv[3];
                      int len = Integer.parseInt(recv[4]);
                      if (len < 8192)
                      {
                          int count = dis.available();
                          byte[] bs = new byte[count];
                          dis.read(bs);
                          byte[] decipheredFileByte = decipherFile(bs, mode, secretKey);
                          File decipheredFile = new File(fileName);
                          FileOutputStream out = new FileOutputStream(decipheredFile);
                          out.write(decipheredFileByte);
                          out.close();
                      }
                      else
                      {
                          
                      }
                      
                  }
                  else
                  {              
                      int count = dis.available();
                      byte[] bs = new byte[count];
                      dis.read(bs);
                      String msg = new String(bs);
                      /*while((line = reader.readLine()) != null)
                      {
                          //counter += line.getBytes().length;
                          msg += line;
                      }*/
                      String decyptedMsg = decipherMsg(msg, mode, secretKey);
                      Platform.runLater(() ->  alertReceiveMessage(decyptedMsg));
                      setPassword("");
                  }
            }
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
    
}
