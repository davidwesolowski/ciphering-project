/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk;

import java.awt.MouseInfo;
import java.awt.PointerInfo;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
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
import javafx.scene.control.cell.ProgressBarTableCell;
import javafx.stage.FileChooser;
import javax.crypto.Cipher;
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
    private PublicKey publicKey;
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
        //String psw = createDialog();
        //setPassword(psw);
        
        try
        {
            //rsaKeyGenerator();
            
            Thread thread = new Thread(connection);
            thread.start();
            new Thread(new Runnable()
            {
                @Override public void run()
                {
                    try(ServerSocket server = new ServerSocket(50508))
                    {
                        Socket socket2 = server.accept();
                        Thread.sleep(1000);
                        DataInputStream input = new DataInputStream(socket2.getInputStream());
                        byte[] receivedPublicKey = new byte[input.available()];
                        input.read(receivedPublicKey);
                        X509EncodedKeySpec pubKs = new X509EncodedKeySpec(receivedPublicKey);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        publicKey = kf.generatePublic(pubKs);
                    }
                    catch (Exception e)
                    {
                        System.out.println(e);
                    }
                }
            }).start();
            
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
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
    
    public void sendCipherFile()
    {
            String mode = choiceBoxMode.getSelectionModel().getSelectedItem();
            String type = choiceBoxOpt.getSelectionModel().getSelectedItem();

            SecretKey key = sessionKeyGenerator();
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

            if (type.equals("File") && (!mode.equals("")) && (currentFile != null))
            {
                try (Socket socket = new Socket("192.168.0.103", 50502);
                        DataOutputStream output = new DataOutputStream(socket.getOutputStream()))
                 {
                     msgToSend += "file" + "\n";
                     msgToSend += currentFile.getFile().getName() + "\n";
                     int max = 65536;
                     FileInputStream inputStream = new FileInputStream(currentFile.getFile());
                     byte [] inputBytes = new byte[(int) currentFile.getFile().length()];
                     inputStream.read(inputBytes);
                     long startTime = System.nanoTime();
                     byte[] cipheredFile = cipherFile(inputBytes, key);
                     long endTime = System.nanoTime();
                     long elapsed = endTime - startTime;
                     System.out.println(elapsed);
                     msgToSend += cipheredFile.length;
                     output.writeUTF(msgToSend);
                     int fileSize = cipheredFile.length;

                     if (fileSize < max)
                    {
                        output.write(cipheredFile);
                        Platform.runLater(() -> 
                        {
                           jobs.get(jobs.size() -1).setStatus(FileJob.STATUS_DONE);
                           jobs.get(jobs.size() -1).setProgressBar(1.0);
                        });
                    }
                    else
                    {
                        int amountToSend = (fileSize / max) + 1 ;
                        int start = 0;
                        int len = max;
                        while (amountToSend > 0)
                        {
                                if (amountToSend == 1)
                                    len = fileSize - start;
                                output.write(cipheredFile, start, len);
                                System.out.println("wysyłam " + amountToSend );
                                start += len;
                                amountToSend--;
                                double prBar = ((double)start / fileSize);
                                Platform.runLater(() ->  jobs.get(jobs.size() -1).setProgressBar(prBar));
                        }
                        Platform.runLater(() -> 
                        {
                           jobs.get(jobs.size() -1).setStatus(FileJob.STATUS_DONE);
                        });
                    }
                 }
                 catch (Exception e)
                 {
                     System.out.println(e);
                 }
            }
            else
            {
                try (Socket socket = new Socket("192.168.0.103", 50502);
                        DataOutputStream output = new DataOutputStream(socket.getOutputStream()))
                {
                    long startTime = System.nanoTime();
                    String encryptedMsg = cipherMsg(key);
                    long endTime = System.nanoTime();
                    long elapsedTime = endTime - startTime;
                   System.out.println(elapsedTime);
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
    
    public void initKeys(ActionEvent event)
    {
        new Thread(new Runnable()
        {
            @Override public void run()
            {
                try(Socket socket = new Socket("192.168.0.103", 50507);
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream()))
                {
                    PublicKey publicKey = loadPublicKey();
                    output.write(publicKey.getEncoded());
                    System.out.println("Wysylanie publicznego");

                }
                catch (Exception e)
                {
                    System.out.println(e);
                }
            }
        }).start();
    }
    
    public void sendFile(ActionEvent event)
    {
            new Thread(new Runnable() {
                @Override public void run()
                {
                    sendCipherFile();
                }
            }).start();
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
            BigInteger k = new BigInteger(256, new Random(x+y));
            byte[] b = k.toByteArray();
            byte [] secretByte = new byte[32];
            for (int i = 0; i<32; i++)
            {
                 secretByte[i] = b[i];
            }        
            SecretKey secretKey = new SecretKeySpec(secretByte, "AES");
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
            long startTime = System.nanoTime();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            long endTime = System.nanoTime();
            long timeElapsed = endTime - startTime;
            System.out.println(timeElapsed);
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
                break;
           case FileJob.CBC:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.CBC_METHOD, Cipher.ENCRYPT_MODE, key);
                break;
           case FileJob.CFB:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.CFB_METHOD, Cipher.ENCRYPT_MODE, key);
                break;
           case FileJob.OFB:
                encryptedMsg = doCipheringMsg(message, mode, FileJob.OFB_METHOD, Cipher.ENCRYPT_MODE, key);
                break;
        }
        return encryptedMsg;
    }
    
    public byte[] cipherFile(byte[] input, SecretKey key)
    {
        String mode = choiceBoxMode.getSelectionModel().getSelectedItem();
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
        return result;
    }
}
