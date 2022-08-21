#VirusTotal URL reputation project
#VirusTotal API documentation: https://developers.virustotal.com/reference/overview

import requests
import json
import time
import csv 

# https://ao.ms/how-to-do-base64-encoding-in-python/
CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
def to_base_64(string):
    padding = 3 - len(string) % 3 if len(string) % 3 else 0
    binary = ''.join(format(ord(i),'08b') for i in string) + '00'*padding
    return ''.join(CODES[int(binary[i:i+6], 2)] for i in range(0, len(binary), 6))
def from_base_64(string):
    binary = ''.join(format(CODES.find(i),'06b') for i in string)
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)).rstrip('\x00')

def VTrep(site):
    '''Utilizes VirusTotal's API to request URL reputation information and returns the verdict based on it's last_analysis_stats'''
    
    url = "https://www.virustotal.com/api/v3/urls/"
    
    vt_apiKey = "?" #API key needed

    headers = {
        "Accept": "applicaiton/json",
        "x-apikey": vt_apiKey
    }

    to_scan = (to_base_64(site)) 
    new_url = str(url) + str(to_scan)

    response = requests.request("GET", new_url, headers=headers)

    response_json = json.loads(response.content)

    #iterate through nested data
    nest1 = response_json['data']
    nest2 = nest1['attributes']
    nest3 = nest2['last_analysis_stats']

    #Logic to determine URL reputation
    if nest3['malicious'] == 0:
        verdict = "not malicious"
    elif nest3['malicious'] <= 2:
        verdict = "suspicious"
    else:
        verdict = "malicious"

    #sleep 15 seconds; Use for 4 requests/minute restriction of Public API
    time.sleep(15)
    return verdict

def main():
    '''
    Main program call reads in URLs from a CSV file, runs VTrep function, and outputs URLs with reputation to a new CSV file.
    
    Replace file path for CSV reader with a path to a CSV containing URLs.

    Replace file path for CSV writer with desired output location and name. 
    '''

    #read CSV with url indicators
    #replace with path to your file
    with open("/Users/dan/Desktop/VirusTotal_urls.csv", "r") as domain_csv:
        csv_reader = csv.reader(domain_csv)

        #csv to write to 
        with open("/Users/dan/Desktop/VT_funcOutput.csv", "w") as new_file:
            csv_writer = csv.writer(new_file)
            
            #create header for newfile 
            csv_header = ["URL", "Reputation"]
            csv_writer.writerow(csv_header)

            for line in csv_reader:
                line = line[0]
                print(line)
                to_csv = []

                try:
                    final_verdict = VTrep(str(line))
                    to_csv.append(line)
                    to_csv.append(final_verdict)

                    csv_writer.writerow(to_csv)
                except:
                    print("Error")
                    to_csv.append(line)
                    csv_writer.writerow(to_csv)

main()

print("Done")