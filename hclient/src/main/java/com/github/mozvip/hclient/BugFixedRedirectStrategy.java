package com.github.mozvip.hclient;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.http.ProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultRedirectStrategy;

public class BugFixedRedirectStrategy extends DefaultRedirectStrategy {
	
    /**
     * Redirectable methods.
     */
    private static final String[] REDIRECT_METHODS = new String[] {
        HttpGet.METHOD_NAME,
        HttpHead.METHOD_NAME,
        HttpPost.METHOD_NAME
    };	
	
    /**
     * @since 4.2
     */
    @Override
    protected boolean isRedirectable(final String method) {
        for (final String m: REDIRECT_METHODS) {
            if (m.equalsIgnoreCase(method)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * @since 4.1
     */
    @Override
    protected URI createLocationURI(final String location) throws ProtocolException {
        try {
			return RequestFactory.getURI( location );
		} catch (URISyntaxException e) {
			throw new ProtocolException( e.getMessage(), e );
		}
    }    

}
