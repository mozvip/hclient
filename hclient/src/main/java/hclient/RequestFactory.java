package hclient;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RequestFactory {

	private final static int DEFAULT_MAX_REQUESTS_PER_MINUTE = 20;

	private final static Logger LOGGER = LoggerFactory.getLogger( RequestFactory.class );

	private static Map<String, Integer> maxRequestsPerMinuteForHost = new ConcurrentHashMap<String, Integer>();
	private static Map<String, Long> lastRequestForHost = new ConcurrentHashMap<String, Long>();

	static {
		maxRequestsPerMinuteForHost.put("www.amazon.fr", 15);
	}

	public static HttpPost getPost( URL url, URL referer ) {

		URI uri;
		try {
			uri = url.toURI();
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			return null;
		}		
    	HttpPost httppost = new HttpPost( uri );
    	if (referer != null) {
    		httppost.setHeader("Referer", referer.toString());
    	}
    	
    	httppost.setHeader("Accept", "*/*");
    	httppost.setHeader("Accept-Language", "en-US,en;q=0.5");

    	wait( uri.getHost() );

    	return httppost;
	}
	
	public static URI getURI( String url ) throws URISyntaxException {
		String urlString = url.replaceAll("\\s", "%20");		
		String[] elements = urlString.split("/");
		if (elements.length>0) {
			for (int i=2;i<elements.length; i++) {
				elements[i] = elements[i].replace(":", "%3A");
				elements[i] = elements[i].replace("[", "%5B");
				elements[i] = elements[i].replace("]", "%5D");
				elements[i] = elements[i].replace("&", "%26");
				elements[i] = elements[i].replace("'", "%27");		
			}
			urlString = StringUtils.join( elements, '/');
			if (url.endsWith("/")) {
				urlString += "/";
			}
		}		
		
		return new URI( urlString );
	}

	public static HttpGet getGet( URL url, String referer ) throws URISyntaxException {
		HttpGet httpget = new HttpGet( getURI( url.toString() ) );
    	httpget.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
    	httpget.setHeader("Accept-Language", "en-US,en;q=0.5");
    	if (referer != null) {
    		httpget.setHeader("Referer", referer);
    	}

    	wait( url.getHost() );

    	return httpget;
	}

	private static void wait( String host ) {

    	int maxRequestsPerMinute = DEFAULT_MAX_REQUESTS_PER_MINUTE;

    	if (maxRequestsPerMinuteForHost != null && maxRequestsPerMinuteForHost.containsKey( host )) {
	    	maxRequestsPerMinute = maxRequestsPerMinuteForHost.get(host);
    	}

    	int delayBetweenRequests = (1000 * 60) / maxRequestsPerMinute;
    	long nextRequest = System.currentTimeMillis();
    	if (lastRequestForHost.containsKey( host )) {
    		nextRequest = lastRequestForHost.get( host ) + delayBetweenRequests;
    	}

    	while (!(System.currentTimeMillis() > nextRequest) ) {
    		try {
				Thread.sleep( 200 );
			} catch (InterruptedException e) {
			}
    	}

    	lastRequestForHost.put( host, System.currentTimeMillis() );
	}

}
