package net.sourceforge.jradiusclient.jaas;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Title:
 * Description:
 * Copyright:    Copyright (c) 2003
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.2 $
 */
public class RadiusLoginHandler implements CallbackHandler {

    public static final String JAAS_MODULE_KEY = "JRadiusClientLoginModule";

    /* fields for storing credentials */
    private String name;
    private String password;
    private String clientIP;
	private String hostName;
	private String sharedSecret;
	private int authPort;
	private int acctPort;
	private String callingStationID;
	private int numRetries;
	private int timeout;

    /**
     * Constructor
     * @throws java.lang.IllegalArgumentException if any param is null
     */
    public RadiusLoginHandler(final String name, 
						final String password, 
						final String clientIP,
						final String callingStationID,
						final String radiusHostname,
						final String sharedSecret,
						final int authPort,
						final int acctPort,
						final int retries,
						final int timeout) {
        if (name == null || password == null || clientIP == null) {
            throw new IllegalArgumentException("Arguments cannont be null");
        }
        this.name = name;
        this.password = password;
        this.clientIP = clientIP;
		this.callingStationID = callingStationID;
		this.hostName = radiusHostname;
		this.sharedSecret = sharedSecret;
		this.authPort = authPort;
		this.acctPort = acctPort;
		this.numRetries = retries;
		this.timeout = timeout;
    }

    /**
     * If this method returns the login was successfull, but if it throws an
     * exception it failed.  There are subclasses of LoginException for the
     * specific kinds of failures.
     */
    public void login() throws LoginException {
        LoginContext loginContext = new LoginContext(JAAS_MODULE_KEY, this);
        loginContext.login();
    }

    /**
     * Callback Handler for the login service
     * @param javax.security.auth.callback.Callback array of callback objects to
     * fill in with requested data
     * @throws java.io.IOException
     * @throws javax.security.auth.callback.UnsupportedCallbackException
     */
    public void handle(Callback[] callback) throws IOException, UnsupportedCallbackException {
        for(int i = 0; i < callback.length; i++){
            handle(callback[i]);
        }
    }

    protected void handle(Callback callback) throws UnsupportedCallbackException {
        if (callback instanceof NameCallback) {
            ((NameCallback)callback).setName(name);
        }else if (callback instanceof PasswordCallback) {
            ((PasswordCallback)callback).setPassword(password.toCharArray());
        }else if (callback instanceof TextInputCallback) {
            // this code assumes that there will only be one TextInputCallback and it is used for the client IP
            ((TextInputCallback)callback).setText(clientIP);
        }else if (callback instanceof RadiusCallback) {
			RadiusCallback radiusCallback = (RadiusCallback)callback;
			radiusCallback.setHostName(this.hostName);
			radiusCallback.setSharedSecret(this.sharedSecret);
			radiusCallback.setAuthPort(this.authPort);
			radiusCallback.setAcctPort(this.acctPort);
			radiusCallback.setCallingStationID(this.callingStationID);
			radiusCallback.setNumRetries(this.numRetries);
			radiusCallback.setTimeout(this.timeout);
		}else {
            throw new UnsupportedCallbackException(callback);
        }
    }
}

