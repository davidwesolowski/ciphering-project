/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk;

import java.io.File;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleStringProperty;

/**
 *
 * @author Dawid
 */
public class FileJob 
{
    public static final String STATUS_WAITING = "waiting";
    public static final String STATUS_INIT = "initializing";
    public static final String STATUS_DONE = "done";
    public static final String PLIK = "File";
    public static final String ECB = "ECB";
    public static final String CBC = "CBC";
    public static final String CFB = "CFB";
    public static final String OFB = "OFB";
    public static final String ECB_METHOD = "AES/ECB/PKCS5Padding";
    public static final String CBC_METHOD = "AES/CBC/PKCS5Padding";
    public static final String CFB_METHOD = "AES/CFB/PKCS5Padding";
    public static final String OFB_METHOD = "AES/OFB/PKCS5Padding";


    private File convertFile;
    private SimpleStringProperty fileName;
    private SimpleStringProperty mode;
    private DoubleProperty progressBar;
    private SimpleStringProperty status;
    private SimpleStringProperty message;

    public FileJob(File f)
    {
        this.convertFile = f;
        this.fileName = new SimpleStringProperty(f.getName());
        this.mode = new SimpleStringProperty("ECB");
        this.status = new SimpleStringProperty(STATUS_WAITING);
        this.progressBar = new SimpleDoubleProperty();
        this.message = new SimpleStringProperty("");
    }

    public File getFile()
    {
        return convertFile;
    }

    /*public SimpleStringProperty getMessageProperty()
    {
        return this.message;
    }*/

    public SimpleStringProperty getFileNameProperty()
    {
        return this.fileName;
    }

    public void setStatus(String s)
    {
        this.status.set(s);
    }

    public String getStatus()
    {
        return this.status.get();
    }

    public SimpleStringProperty getStatusProperty()
    {
        return this.status;
    }

    public void setProgressBar(Double progress)
    {
        this.progressBar.set(progress);
    }

    public Double getProgressBar()
    {
        return this.progressBar.get();
    }

    public DoubleProperty getProgressProperty()
    {
        return this.progressBar;
    }
    
    public void setMode(String m)
    {
        this.mode.set(m);
    }

    public String getMode()
    {
        return this.mode.get();
    }

    public SimpleStringProperty getModeProperty()
    {
        return this.mode;
    }
}
