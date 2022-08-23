VirusTotal URL reputation project 

This project aims to simplify the process of obtaining a VirusTotal URL reputation for URL indicators. This is especially effective for use cases that involve investigating dozens to hundreds of URLs. By leveraging VirusTotal’s API and python’s requests and csv modules especially, the script will significantly cut down on an analyst’s investigation. 

To begin, be sure to read up on VirusTotal’s API documentation.  Note that per the documentation for free tier API key, it “Must not be used in business workflows, commercial products or services.” The rate limiting of 4 requests/min should be noted as well. 

Link for further information and to obtain an API key:
https://developers.virustotal.com/reference/overview


To use, make sure to replace the “?” In line 24 with a valid API key within quotations.
	If using a premium API key, comment out line 52 with “#”. This is the logic that 	handles the rate limiting of the free tier key. 

Replace the file path & file name in line 66 with a valid CSV file on your local machine containing the URL indicators to be researched.
	Each row should contain one plaintext URL in the first column of the file
	Many security tools have an export option where CSV may be specified if a log export is to be used for this input file

Replace the file path & give a valid name to the output file specified on line 70.
	This file will be overwritten after the first execution unless an alternate filename is specified. 
