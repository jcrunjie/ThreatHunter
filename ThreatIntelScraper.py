# Authors: Jessica Chen, Eli Windle
# Emails: Jessica.Chen@gdit.com, Eli.Windle@gdit.com
# Date of release: N/A
# Description: Scrapes IOCs from threat intel reports, formulates the IOCs into S1 and Logger queries runs the queries automatically.
# Goal: This script automates parts of the threat hunting process to save time and money for GDIT
# Features: deduplicates IOCs, excludes non-routable IPs to reduce noise

import re, regex, os, json, urllib, requests, optparse, time, datetime
from bs4 import BeautifulSoup
from datetime import date

# a workaround to make sets JSON serializable
def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj

# Implementing the ability to specify command line arguments when running this script
parser = optparse.OptionParser()
parser.add_option("-f", "--format", dest="format", help="Output file format (csv/json)")
parser.add_option("-o", "--output", dest="output", help="Output file name to save results to (do not specify file extension, the script will take care of that)")
parser.add_option("-p", "--PDF", dest="PDF", help="File path to the threat intel in PDF format to scrape IOCs from")
parser.add_option("-u", "--URL", dest="URL", help="URL to the threat intel in online format to scrape IOCs from")
(options, arguments) = parser.parse_args()

# FINAL DO NOT CHANGE KEY NAMES - Initiating a dictionary of different types of IOCs
IOCs = {'MD5': set(), 'SHA1': set(), 'SHA256': set(), 'IPs': set(), 'domains': set(), 'URLs': set()}


# Description: method that finds hashes (MD5, SHA1, SHA256)
# Parameter: string - a string to find the hashes from
# Return: a dictionary with keys = MD5, SHA1, SHA256. values = a set of hashes to each corresponding type
def hash_finder(string):
    # Regex patterns that matches any consecutive characters without whitespace (length is based on each hash type)
    pattern64 = re.compile(r'\s[0-9a-f]{64}\s')
    pattern40 = re.compile(r'\s[0-9a-f]{40}\s')
    pattern32 = re.compile(r'\s[0-9a-f]{32}\s')

    matches64 = pattern64.finditer(string)
    matches40 = pattern40.finditer(string)
    matches32 = pattern32.finditer(string)

    # Initiating empty sets for the hashes
    SHA256hashes = set()
    SHA1hashes = set()
    MD5hashes = set()

    # Initiating empty dictionary to store final result
    hashes = {}
    for match in matches64:  # for SHA256
        span = match.span()  # gets the span of the whole text and assigns a variable
        hashstr = string[span[0] + 1:span[1] - 1]  # pulls the str value away from the location and assigns a variable
        SHA256hashes.add(hashstr) # adds the hash to the set

    for match in matches40:  # for SHA1
        span = match.span()
        hashstr = string[span[0] + 1:span[1] - 1]
        SHA1hashes.add(hashstr)

    for match in matches32:  # for MD5
        span = match.span()
        hashstr = string[span[0] + 1:span[1] - 1]
        MD5hashes.add(hashstr)

    # Adding the sets of hashes to the hashes dictionary corresponding to their keys
    hashes.update({'SHA256': SHA256hashes, 'SHA1': SHA1hashes, 'MD5': MD5hashes})
    return hashes

# Description: method that finds URLs and Domains
# Parameter: string - a string to find the URLs and Domains from
# Return: a dictionary with keys = URLs, domains. values = a set of URLs, a set of domains
def URL_and_domain_finder(string):

    # Initializing empty sets to save the results to
    URLs = set()
    domains = set()

    # Getting a list of valid top-level-domains which will be used for regex pattern matching
    url = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'

    response = urllib.request.urlopen(url)
    webContent = response.read()

    with open('tld.txt', 'wb') as tld:
        tld.write(webContent.lower())

    # finding the URLs and domains using regex and updating the URLs and domains sets
    with open('tld.txt', 'r') as tld:
        joinedTLDs = '|'.join(line.strip() for line in tld)
        potentialURLs = re.findall("[:/\[\]]{,5}([a-zA-Z0-9$\-_.+!*'()/,\[\]]{0,}[\[\]\.]{1,3}(" + joinedTLDs + ")[a-zA-Z0-9$-_.+!*'(),\[\]]{0,})", string)
        for url in potentialURLs:
            if '[' in url[0] and ']' in url[0]:
                URLs.add(re.sub('\[(\.|dot)\]', '.', url[0]))

        potentialDomains = regex.findall('(([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9])\[(\.|dot)\]('+ joinedTLDs + '))[\[\.\s/\'\"]', string)
        for domain in potentialDomains:
            # tlds = tld.read()
            # print(domain[1])
            # if domain[2] in tlds:
            # print(domain[0] + ' ' + domain[1] + ' ' + domain[2])
            domains.add(domain[1] + '.' + domain[3])

    return {'URLs': URLs, 'domains': domains}

# Description: method that finds IPs
# Parameter: string - a string to find the IPs from
# Return: a dictionary with keys = IPs. values = a set of IPs
def IP_finder(string):
    pattern = re.compile(r'[0-9]{1,3}(\.|\[\.\]|\[dot\])[0-9]{1,3}(\.|\[\.\]|\[dot\])[0-9]{1,3}(\.|\[\.\]|\[dot\])[0-9]{1,3}')

    matches = pattern.finditer(string)

    # Empty set for IP's
    IPaddr = set()
    for match in matches:
        span = match.span()
        ipstr = string[span[0]:span[1]]

        # Adding found IP's to the set
        IPaddr.add(re.sub('\[(\.|dot)\]', '.', ipstr))

    return ({'IPs': IPaddr})

# Description: a method that performs the scraping by utilizing the finder methods for each IOC type and saving the results to an output file
# Parameter: report_content - the threat report to scrape against in a string format,
#            out_file - the file name to save results to, do not include file extensions here,
#            out_format - the format of the output file, specify either csv or json
# Return: nothing, the results will be saved to the file the user sepcifies and saved to the output folder of where this script is located at
def scraper(report_content, out_file, out_format):
    os.system(f'md output\\{out_file}')
    with open(f'output/{out_file}/IOCs.{out_format}', 'w+') as IOCoutput:
        # Finding and updating hashes to the IOCs dictionary
        IOCs.update(hash_finder(report_content))

        # Finding and updating URls and domains to the IOCs dictionary
        IOCs.update(URL_and_domain_finder(report_content))

        # Finding and updating IPs to the IOCs dictionary
        IOCs.update(IP_finder(report_content))

        # Saving the results into an output file that the user specified
        if out_format.lower() == 'json':
            json.dump(IOCs, IOCoutput, indent=2, default=serialize_sets)
        if out_format.lower() == 'csv':
            s = ''
            for key in IOCs:
                if len(IOCs[key]) != 0:
                    s += str(key) + "," + ",".join(IOCs[key]) + "\n"
            IOCoutput.write(s)

    # Formulating IOCs into S1 and Logger queries
    with open(f'output/{out_file}/Queries.txt', 'w+') as queriesOutput:
        s1 = []
        logger = []
        for key in IOCs:
            if len(IOCs[key]) != 0:
                if key == 'MD5':
                    s1.append('tgtFileMd5 in (\"' + '\",\"'.join(IOCs[key]) + '\")')
                if key == 'SHA1':
                    s1.append('tgtFileSha1 in (\"' + '\",\"'.join(IOCs[key]) + '\")')
                if key == 'SHA256':
                    s1.append('tgtFileSha256 in (\"' + '\",\"'.join(IOCs[key]) + '\")')
                if key == 'IPs':
                    s1.append('DstIP in (\"' + '\",\"'.join(IOCs[key]) + '\")')
                if key == 'domains':
                    s1.append('Url In Contains Anycase (\"' + '\",\"'.join(IOCs[key]) + '\")')
                if key == 'URLs':
                    s1.append('Url In Contains Anycase (\"' + '\",\"'.join(IOCs[key]) + '\")')
        queriesOutput.write(" OR ".join(s1))

        # using S1 API to run the query and saving the results to a file
        today = date.today()
        current_utc = datetime.datetime.utcnow()
        today_minus_30days = today - datetime.timedelta(days=30)

        body = {"toDate": current_utc.strftime('%Y-%m-%dT%H:%M:%S.%f%ZZ'),
                "fromDate": f"{today_minus_30days}T{current_utc.strftime('%H:%M:%S.%f%Z')}Z",
                "query": " OR ".join(s1)
                }

        post_query = 'https://usgovwe1-gdit.s1gov.net/web/api/v2.1/dv/init-query'
        get_query_status = 'https://usgovwe1-gdit.s1gov.net/web/api/v2.1/dv/query-status?queryId='
        get_query_events = 'https://usgovwe1-gdit.s1gov.net/web/api/v2.1/dv/events?queryId='

        headers = {
            'Authorization': 'APIToken 8PH0lVxGl8dy9kDxBC25xGGkhOC1Y1hvzUcIgv1yPJrwyV2IROYIckmeLoF6FVVtYv29nsiaduOC8Lmz',
            'Content-Type': 'application/json'}

        runQuery = requests.post(post_query, json=body, headers=headers)
        queryID = runQuery.json()['data']['queryId']

        while True:
            checkStatus = requests.get(get_query_status + queryID, headers=headers).json()
            print(f"{checkStatus['data']['responseState']} {checkStatus['data']['progressStatus']}%")
            progressStatus = checkStatus['data']['progressStatus']
            if progressStatus != None and progressStatus == 100:
                break;
            time.sleep(3)

        with open(f'output/{out_file}/query_results.json', 'w+') as query_output:
            results = requests.get(get_query_events + queryID, headers=headers).json()
            json.dump(results, query_output, indent=2)
#'SHA1': set(), 'SHA256': set(), 'IPs': set(), 'domains': set(), 'URLs'
        # S1.write(s1_string)
        #
        # for ip in IOCs['IPs']:
        #     logger_ips.append(f'sourceAddress = "{ip}" or destinationAddress = "{ip}"')
        #
        # for url in IOCs['URLs']:
        #     logger_domains_urls.append(f'"{url}"')
        # for domain in IOCs['domains']:
        #     logger_domains_urls.append(f'"{domain}"')
        # logger_string += ' OR '.join(logger_ips) + "\n"
        # logger_string += ' OR '.join(logger_domains_urls)
        # logger.write(logger_string)

# Scraping IOCs based on report format
if options.format is None:
    print("Please specify an output file format to save results to (see help menu for options -h)")
elif options.format.lower() != 'csv' and options.format.lower() != 'json':
    print("Please specify an acceptable output file format (see help menu for options -h)")
elif options.output is None:
    print("Please specify an output file name to save results to (see help menu for options -h)")
elif options.PDF is None and options.URL is None:
    print("Please specify an input format and the corresponding threat report to scrape against (see help menu for options -h)")
elif options.PDF is not None and options.URL is not None:
    print("Please specify only one input to scrape against (see help menu for options -h)")
elif options.PDF is not None:
    # Running a command to extract text from the report PDF to a text file
    os.system(f'pdf2txt.py "{options.PDF}" > convertedPDF.txt')

    with open('convertedPDF.txt', 'r') as report:
        # Reading the report text file into a string
        reportContent = report.read()

        # Running the scraper function
        scraper(reportContent, options.output, options.format)

    # Deleting the extra files created in the process
    os.system('del convertedPDF.txt')
else:
    # Extracting text from the report website
    url = options.URL
    res = requests.get(url)
    html_page = res.content
    soup = BeautifulSoup(html_page, 'html.parser')
    text = soup.find_all(text=True)
    output = ''
    blacklist = [
        '[document]',
        'noscript',
        'header',
        'html',
        'meta',
        'head',
        'input',
        'script',
        # there may be more elements you don't want, such as "style", etc.
    ]

    for t in text:
        if t.parent.name not in blacklist:
            output += '{} '.format(t)

    # Running the scraper function
    scraper(output, options.output, options.format)