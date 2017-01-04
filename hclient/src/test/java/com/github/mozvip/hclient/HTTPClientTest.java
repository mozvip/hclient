package com.github.mozvip.hclient;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

import org.apache.http.cookie.Cookie;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Node;

import com.github.mozvip.hclient.HTTPClient;
import com.github.mozvip.hclient.SimpleResponse;
import com.github.mozvip.hclient.core.WebDocument;

import junit.framework.Assert;

public class HTTPClientTest {
	
	private HTTPClient client = HTTPClient.getInstance();
	
	@BeforeClass
	public static void init() {
	}

	@Test
	public void testGetZip() throws IOException, URISyntaxException {
		SimpleResponse response = client.get( "http://www.dzone.com/sites/all/files/Log4jExample4.zip" );
		Assert.assertEquals(response.getContentType(), "application/zip");
	}
	
	@Test
	public void testGithub() throws IOException, URISyntaxException {
		WebDocument document = client.getDocument( "https://github.com/antlr/antlr4" );
		String updatedAt = document.jsoup("time.updated").attr("datetime");
		Assert.assertNotNull( updatedAt );
	}

	@Test
	public void testGetReddit() throws Exception {
		WebDocument document = client.getDocument( "https://www.reddit.com/r/programming/", 0 );
		List<Node> titles = document.evaluateXPath("//a[contains(@class, 'title')]/text()");
		Assert.assertTrue( titles.size() > 0 );
	}

	@Test
	public void testAmazonCookies() throws IOException, URISyntaxException {
		client.getDocument("http://www.amazon.fr", 0);
		List<Cookie> cookies = client.getCookieStore().getCookies();
		Assert.assertTrue( cookies.size() > 0 );
	}

}
