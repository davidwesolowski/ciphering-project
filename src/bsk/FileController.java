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
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.ResourceBundle;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.cell.ProgressBarTableCell;
import javafx.stage.FileChooser;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dawid
 */
public class FileController extends AbstractCipher implements Initializable
{
    @FXML
    TableView<FileJob> fileTable;
    @FXML
    TableColumn<FileJob, String> fileColumn;
    @FXML
    TableColumn<FileJob, Double> progressColumn;
    @FXML
    TableColumn<FileJob, String> statusColumn;
    @FXML
    TextField messageField;
   @FXML
    ChoiceBox<String> choiceBoxMode = new ChoiceBox<String>();
    @FXML
    ChoiceBox<String> choiceBoxOpt = new ChoiceBox<String>(); 
    ObservableList<FileJob> jobs = FXCollections.observableArrayList();    
    ObservableList<String> modes = FXCollections.observableArrayList("ECB", "CBC", "CFB", "OFB");
    ObservableList<String> opt = FXCollections.observableArrayList("File", "Text");
    private ConnectionThread connection = new ConnectionThread();
    private Socket socket;
    private String password;
    private FileJob currentFile;
    
    public void setPassword(String psw)
    {
        this.password = psw;
    }
    
    @Override
    public void initialize(URL url, ResourceBundle rb)
    {
        fileColumn.setCellValueFactory(p -> p.getValue().getFileNameProperty());
        progressColumn.setCellFactory(ProgressBarTableCell.<FileJob>forTableColumn());
        progressColumn.setCellValueFactory(p -> p.getValue().getProgressProperty().asObject());
        statusColumn.setCellValueFactory(p -> p.getValue().getStatusProperty());
        fileTable.setItems(jobs);
        choiceBoxOpt.setItems(opt);
        choiceBoxMode.setItems(modes);
        String psw = createDialog();
        setPassword(psw);
        
        try
        {
            rsaKeyGenerator();
            PublicKey publicKey = loadPublicKey();
            PrivateKey privateKey = loadPrivateKey();
            SecretKey key = sessionKeyGenerator();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte [] cipherSKey = cipher.doFinal(key.getEncoded());
            FileOutputStream outSKey = new FileOutputStream("D:\\Users\\Dawid\\Desktop\\BSK\\bskv2\\BSK\\keys\\sKey.key");
            outSKey.write(cipherSKey);
            outSKey.close();
            
            File f = new File("D:\\Users\\Dawid\\Desktop\\BSK\\bskv2\\BSK\\keys\\sKey.key");
            FileInputStream inputSKey = new FileInputStream(f);
            byte [] sKeyBytes = new byte[(int)f.length()];
            inputSKey.read(sKeyBytes);
            Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher2.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptSKey = cipher2.doFinal(sKeyBytes);

            String sDecryptKey = new String(decryptSKey);
            inputSKey.close();
            
            Thread thread = new Thread(connection);
            thread.start();
            //this.socket = new Socket("localhost", 50505);
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
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
    
    public void chooseFile(ActionEvent event)
    {
        FileChooser fileChooser = new FileChooser();
        List<File> selectedFile = fileChooser.showOpenMultipleDialog(null);
        if (selectedFile == null)
            return;
        this.currentFile = new FileJob(selectedFile.get(0));
        for(File f:selectedFile)
        {
            jobs.add(new FileJob(f));
        }
    }
    
    public void sendFile(ActionEvent event)
    {
        String mode = choiceBoxMode.getSelectionModel().getSelectedItem();
        SecretKey key = sessionKeyGenerator();
        PublicKey publicKey = loadPublicKey();
        Cipher cipher;
        String msgToSend = "";
        msgToSend += mode + "\n";
        try {
             cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
             cipher.init(Cipher.ENCRYPT_MODE, publicKey);
             byte [] cipherSKey = cipher.doFinal(key.getEncoded());
             String encryptedKey = Base64.getEncoder().encodeToString(cipherSKey);
             msgToSend += encryptedKey + "\n";
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        
        if (choiceBoxOpt.getSelectionModel().getSelectedItem() == "File")
        {
             /*jobs.forEach((job) -> {
                 if (job.getStatus() != "done")
                     cipherFile(job);
             });*/
            try (Socket socket = new Socket("localhost", 50506);
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream()))
             {
                 msgToSend += "file" + "\n";
                 msgToSend += this.currentFile.getFile().getName() + "\n";
                 int max = 65536;
                 FileInputStream inputStream = new FileInputStream(this.currentFile.getFile());
                 byte [] inputBytes = new byte[(int) this.currentFile.getFile().length()];
                 inputStream.read(inputBytes);
                 byte[] cipheredFile = cipherFile(inputBytes, key);
                 msgToSend += cipheredFile.length;
                 output.writeUTF(msgToSend);
                 int fileSize = cipheredFile.length;

                 if (fileSize < max)
                {
                    output.write(cipheredFile);
                }
                else
                {
                    int amountToSend = (fileSize / max) + 1 ;
                    //int fileSize = inputBytes.length;
                    int start = 0;
                    int len = max;
                    while (amountToSend > 0)
                    {
                            if (amountToSend == 1)
                                len = fileSize - start;
                            output.write(cipheredFile, start, len);
                            System.out.println("wysyłam " + amountToSend );
                            //output.write(inputBytes, start, len);
                            start += len;
                            amountToSend--;
                    }
                }
             }
             catch (Exception e)
             {
                 System.out.println(e);
             }
        }
        else
        {
            try (Socket socket = new Socket("localhost", 50506);
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream()))
            {
                String encryptedMsg = cipherMsg(key);
                msgToSend += "message" + "\n";
                output.writeUTF(msgToSend);
                String encrMsgToSend = encryptedMsg;
                output.write(encrMsgToSend.getBytes());
                output.close();
                System.out.println("Wysylanie");
            }
            catch (Exception e)
            {
                System.out.println(e);
            }
        }
    }
    
    public PublicKey loadPublicKey()
    {
        try
        {
            Path publicPath = Paths.get(publicKeyPath);
            byte[] publicKeyBytes = Files.readAllBytes(publicPath);
            X509EncodedKeySpec pubKs = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(pubKs);
            return pub;
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        return null;
    }
   
    public SecretKey sessionKeyGenerator()
    {
        PointerInfo pointer = MouseInfo.getPointerInfo();
        int x = pointer.getLocation().x;
        int y = pointer.getLocation().y;
        SecretKey key = null;
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            BigInteger k = new BigInteger(256, new Random(x+y));
            byte[] b = k.toByteArray();
            byte [] secretByte = new byte[32];
            //System.out.println("secret rozmiar:     "+b.length);
            /*if (b.length == 32)
            {
                for (int i = 0; i<32; i++)
                {
                     secretByte[i] = b[i];
                }
            }
            else
            {
                for (int i = 0; i<32; i++)
                {
                     secretByte[i] = b[i+1];
                }
            }*/
            for (int i = 0; i<32; i++)
            {
                 secretByte[i] = b[i];
            }        
            SecretKey secretKey = new SecretKeySpec(secretByte, "AES");
            //SecretKey secretKey = keyGen.generateKey();
            return secretKey;
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        return key;
    }
    
    public byte[] encyptPrivateKey(byte[] privateKey)
    {
        try
        {       
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey secretKey = hashPassword(password);
            byte[] iv = { 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            byte[] encryptedPrivateKey = cipher.doFinal(privateKey);
            return encryptedPrivateKey;
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
        return null;
    }
    
    public void rsaKeyGenerator()
    {
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            Key publicKey = kp.getPublic();
            Key privateKey = kp.getPrivate();
            FileOutputStream publicOut = new FileOutputStream(publicKeyPath);
            FileOutputStream privateOut = new FileOutputStream(privateKeyPath);
            byte [] encryptedPrivateKey = encyptPrivateKey(privateKey.getEncoded());
            publicOut.write(publicKey.getEncoded());
            privateOut.write(encryptedPrivateKey);
            publicOut.close();
            privateOut.close();   
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
    }
    
    public String cipherMsg(SecretKey key)
    {
        String mode = choiceBoxMode.getSelectionModel().getSelectedItem();
        String message = messageField.getText();
        String encryptedMsg = "";
        switch (mode)
        {
            case FileJob.ECB:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.ECB_METHOD, Cipher.ENCRYPT_MODE, key);
                //doCipheringMsg(encryptedMsg, mode, FileJob.ECB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
           case FileJob.CBC:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.CBC_METHOD, Cipher.ENCRYPT_MODE, key);
                //doCipheringMsg(encryptedMsg, mode, FileJob.CBC_METHOD, Cipher.DECRYPT_MODE, key);
                break;
           case FileJob.CFB:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.CFB_METHOD, Cipher.ENCRYPT_MODE, key);
                //doCipheringMsg(encryptedMsg, mode, FileJob.CFB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
           case FileJob.OFB:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.OFB_METHOD, Cipher.ENCRYPT_MODE, key);
                //doCipheringMsg(encryptedMsg, mode, FileJob.OFB_METHOD, Cipher.DECRYPT_MODE, key);
                break;
        }
        return encryptedMsg;
    }
    
    public byte[] cipherFile(byte[] input, SecretKey key)
    {
        String mode = choiceBoxMode.getSelectionModel().getSelectedItem();
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
               result = doCipheringFile(input, mode, FileJob.ECB_METHOD, Cipher.ENCRYPT_MODE, key);                  
                break;
            case FileJob.CBC:
                result = doCipheringFile(input, mode, FileJob.CBC_METHOD, Cipher.ENCRYPT_MODE, key);
                break;
            case FileJob.CFB:
                result =  doCipheringFile(input, mode, FileJob.CFB_METHOD, Cipher.ENCRYPT_MODE, key);
                break;
            case FileJob.OFB:
                 result = doCipheringFile(input, mode, FileJob.OFB_METHOD, Cipher.ENCRYPT_MODE, key);
                break;
        }
        //Platform.runLater(() -> job.setStatus(FileJob.STATUS_DONE));
        return result;
    }
}
