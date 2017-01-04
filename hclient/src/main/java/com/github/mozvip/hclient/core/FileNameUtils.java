package com.github.mozvip.hclient.core;

public class FileNameUtils {
	
	public static String sanitizeFileName( String fileName ) {
		String cleanFileName = fileName.replace('?', '¿');
		cleanFileName = cleanFileName.replace('é', 'e');	// FIXME : replace all accents 
		cleanFileName = cleanFileName.replaceAll("[\\|\\:\\*/\"]", " ");
		cleanFileName = cleanFileName.replaceAll("\\s+", " ").trim();
		while (cleanFileName.endsWith(".")) {
			cleanFileName = cleanFileName.substring(0, cleanFileName.length() - 1);
		}
		return cleanFileName;
	}	

}
