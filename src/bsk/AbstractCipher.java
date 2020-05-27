/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import javafx.scene.control.TextInputDialog;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dawid
 */
public abstract class AbstractCipher 
{
    protected String publicKeyPath = "D:\\Users\\Dawid\\Desktop\\BSK\\bskv2\\BSK\\keys\\public\\publicKey.key";
    protected String privateKeyPath = "D:\\Users\\Dawid\\Desktop\\BSK\\bskv2\\BSK\\keys\\private\\privateKey.key";
    
    public String createDialog()
    {
        DialogPassword dPwd = new DialogPassword();
        dPwd.setHeaderText("Enter a password");
        Optional<String> result = dPwd.showAndWait();
        if (result.isPresent())
        {
           return result.get();
        }
        return null;
    }
    
    public String doCipheringMsg(String msg, String mode, String method, int cipherMode, SecretKey key)
    {
        try
        {
            Cipher cipher = Cipher.getInstance(method);
            if (!mode.equals("ECB"))
            {
                byte[] iv = { 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                IvParameterSpec ivspec = new IvParameterSpec(iv);
                cipher.init(cipherMode, key, ivspec);
            }
            else
            {
                  cipher.init(cipherMode, key);
            }
            String output = "";
            byte [] text;
            if (cipherMode == Cipher.DECRYPT_MODE)
            {
                text = cipher.doFinal(Base64.getDecoder().decode(msg));
                output = new String(text);
            }
            else
            {
                 text = cipher.doFinal(msg.getBytes("UTF-8"));
                 output = Base64.getEncoder().encodeToString(text);
            }
            return output;
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        return null;
    }
    
    public byte[] doCipheringFile(byte[] inputBytes, String mode, String method, int cipherMode, SecretKey key)
    {
        try
            {
                Cipher cipher;
                cipher = Cipher.getInstance(method);
                 if (!mode.equals( "ECB"))
                {
                    byte[] iv = { 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                    IvParameterSpec ivspec = new IvParameterSpec(iv);
                    cipher.init(cipherMode, key, ivspec);
                }
                 else
                 {
                       cipher.init(cipherMode, key);
                 }
                byte [] outputBytes = cipher.doFinal(inputBytes);
                
                return outputBytes;
            }
            catch (Exception e)
            {
                System.out.println(e);
            }
        return null;
    }
    
    public SecretKey hashPassword(String password)
    {
        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
            SecretKey secretKey = new SecretKeySpec(hashedPassword, "AES");
            return secretKey;
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        return null;
    }
    

}

