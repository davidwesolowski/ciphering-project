/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javax.crypto.Cipher;
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
    private static int port = 50506;
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
   
    public String randomText(int n)
    {
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvxyz"; 
        StringBuilder str = new StringBuilder("");
        
        for (int i=0; i< n; i++)
        {
            if (i%200 == 0)
                str.append("\n");
            int index = (int) (AlphaNumericString.length()*Math.random());
            str.append(AlphaNumericString.charAt(index));
        }
        return str.toString();
    }
    
     @Override 
    public void run()
    {
        try (ServerSocket server = new ServerSocket(port)) {
            
            Platform.runLater(() -> {
                String psw = createDialog();
                setPassword(psw);
            });
            
            while(this.password.equals(""))
            {
                System.out.print("");
            }
            
            while (true)
            {
                  socket = server.accept();
                  Thread.sleep(1000);
                  DataInputStream dis = new DataInputStream(socket.getInputStream());

                  String[] recv = dis.readUTF().split("\n");
                  String mode = recv[0];
                  String s = recv[1];
                  
                  byte[] key = Base64.getDecoder().decode(s);         
                  String type = recv[2];
                  
                  PrivateKey pvt = loadPrivateKey();

                  if (pvt == null)
                  {
                      if (type.equals("file"))
                      {
                          String fileName = recv[3];
                          int len = Integer.parseInt(recv[4]);
                          int constLen = 65536;
                          int amountToReceive = (len / constLen) + 1;
                          byte[] recvFile = new byte[len];
                          int start = 0;
                          while (amountToReceive > 0)
                          { 
                             if (amountToReceive == 1)
                                constLen = len - start;
                                dis.read(recvFile, start, constLen);
                                start += constLen;
                                amountToReceive--;
                          }
                          File f = new File(fileName);
                          FileOutputStream out = new FileOutputStream(f);
                          String text = randomText(5000);
                          out.write(text.getBytes());
                          out.close();
                          dis.close();
                      }
                      else 
                      {
                          String text = randomText(100);
                          Platform.runLater(() ->  alertReceiveMessage(text));
                      }
                  }
                  else 
                  {
                        Cipher cipherKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipherKey.init(Cipher.DECRYPT_MODE, pvt);
                        byte [] decryptedByteKey =cipherKey.doFinal(key);
                        SecretKey secretKey = new SecretKeySpec(decryptedByteKey, "AES");

                        if (type.equals("file"))
                        {              
                            String fileName = recv[3];
                            int len = Integer.parseInt(recv[4]);
                            int max = 65536;
                            if (len < max)
                            {
                                byte[] bs = new byte[len];
                                dis.read(bs);
                                byte[] decipheredFileByte = decipherFile(bs, mode, secretKey);
                                File decipheredFile = new File(fileName);
                                FileOutputStream out = new FileOutputStream(decipheredFile);
                                out.write(decipheredFileByte); 
                                out.close();
                            }
                            else
                            {
                                int constLen = max;
                                int amountToReceive = (len /max) + 1;
                                byte[] recvFile = new byte[len];
                                int start = 0;
                                while (amountToReceive > 0)
                                {
                                    if (amountToReceive == 1)
                                      constLen = len - start;
                                    dis.read(recvFile, start, constLen);
                                    start += constLen;
                                    amountToReceive--;
                                    Thread.sleep(10);
                                }
                                byte[] decipheredFileByte = decipherFile(recvFile, mode, secretKey);
                                File decipheredFile = new File(fileName);
                                FileOutputStream out = new FileOutputStream(decipheredFile);
                                out.write(decipheredFileByte);
                                out.close();
                            }
                        }
                        else
                        {              
                            int count = dis.available();
                            byte[] bs = new byte[count];
                            dis.read(bs);
                            String msg = new String(bs);
                            String decyptedMsg = decipherMsg(msg, mode, secretKey);
                            Platform.runLater(() ->  alertReceiveMessage(decyptedMsg));
                        }
                  } 
            }
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
    
}
