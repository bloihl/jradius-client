package net.sourceforge.jradiusclient.jaas;

import javax.security.auth.callback.Callback;

public class RadiusCallback implements Callback {

    private String hostName;
    private String sharedSecret;
    private int authPort;
    private int acctPort;
    private String callingStationID;
    private int numRetries;
    private int reqTimeout;

    public String getHostName() {
        return hostName;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public int getAuthPort() {
        return authPort;
    }

    public int getAcctPort() {
        return acctPort;
    }

    public String getCallingStationID() {
        return callingStationID;
    }

    public int getNumRetries() {
        return numRetries;
    }
    public int getTimeout(){
        return reqTimeout;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public void setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void setAuthPort(int authPort) {
        this.authPort = authPort;
    }

    public void setAcctPort(int acctPort) {
        this.acctPort = acctPort;
    }

    public void setCallingStationID(String callingStationId){
        this.callingStationID = callingStationId;
    }

    public void setNumRetries(int numRetries) {
        if (numRetries <=0){
            numRetries = 1;
        }
        this.numRetries = numRetries;
    }
    public void setTimeout(int seconds){
        if (seconds < 0) {
            seconds = 0;
        }
        this.reqTimeout = seconds * 1000;
    }
}
