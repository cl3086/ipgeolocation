import argparse
import json
import requests
import simplekml
import socket
import sqlite3
import time
import whois

def main():
    parser = argparse.ArgumentParser(description='Url Analyzer')
    parser.add_argument('-f', '--filename', help='Specify filename with urls', required=True)
    parser.add_argument('-t', '--text', help='Option to get text-base report file', action='store_true')
    parser.add_argument('-d', '--db', help='Option to get SQLite Database file', action='store_true')
    parser.add_argument('-k', '--kml', help='Option to get KML file to visualize geolocations on Google Earth', action='store_true')
    args = parser.parse_args()

    if args.filename == None:
        print('File with urls required!')
        exit(0)
    try:
        with open(args.filename, 'r') as fp:
            analyzeFile(fp, args)
    except IOError as e:
        print("Unable to open file!")
        exit(0)

def analyzeFile(fileHandler, args):
    urls = []
    for url in fileHandler:
        urls.append(url.rstrip())
    fileHandler.close()
    whoIsInfo = retrieveWhoIs(urls)
    dnsInfo = retrieveDNS(urls)
    fingerprints = retrieveServerFingerPrint(urls)
    geolocation = retrieveGeolocation(urls)

    getOutputFiles(args, urls, whoIsInfo, dnsInfo, fingerprints, geolocation)

def retrieveWhoIs(urls):
    allInfo = []
    for url in urls:
        parsedUrl = parseUrl(url)
        try:
            info = whois.whois(parsedUrl)
            strVersion = getStringVersion(info)
        except Exception as e:
            print('Unable to get WhoIs of', url, e)
            info = ''

        allInfo.append(strVersion)
        time.sleep(2)
    return allInfo


def parseUrl(url):
    removeTrailing = url.rstrip('/')
    removeHTTP = removeTrailing.split('//')[-1]
    removeWWW = removeHTTP.split('www.')[-1]
    removeSlashes = removeWWW.split('/')[0]
    dot = '.'
    getDomain = dot.join(removeSlashes.split('.')[-2:])
    return getDomain

def getStringVersion(info):
    strVersion = ''
    for k,v in info.items():
        strVersion += str(k) + ': ' + str(v) + '\n'
    return strVersion


def retrieveDNS(urls):
    IPAddress = []
    for url in urls:
        parsedUrl = parseUrl(url)
        IPAddress.append(socket.gethostbyname(parsedUrl))
    return IPAddress

def retrieveServerFingerPrint(urls):
    fingerprints = []
    for url in urls:
        res = requests.get(url)
        serverInfo = 'Cannot be found.'
        try:
            serverInfo = res.headers['server']
        except Exception:
            pass
        fingerprints.append(serverInfo)
    return fingerprints

def retrieveGeolocation(urls):
    '''
    I used the freegeoip API to get the geolocation. I basically make a request
    given the hostname/IP address and I get location information.
    '''
    geolocation = []
    for url in urls:
        parsedUrl = parseUrl(url)
        apiRequest = 'https://freegeoip.net/json/' + parsedUrl
        res = requests.get(apiRequest)
        geolocation.append(json.loads(res.text.rstrip()))
    return geolocation

def getOutputFiles(args, urls, whoIsInfo, dnsInfo, fingerprints, geolocation):
    if(args.text):
        createTextReport(urls, whoIsInfo, dnsInfo, fingerprints, geolocation)
    if(args.db):
        createDBFile(urls, whoIsInfo, dnsInfo, fingerprints, geolocation)
    if(args.kml):
        createKMLFile(urls, geolocation)

def createTextReport(urls, whoIsInfo, dnsInfo, fingerprints, geolocation):
    fp = open('output.txt', 'w')
    for i in range(len(urls)):
        fp.write('---------------------------------------------------\n\n')
        fp.write('Url: ' + urls[i] + '\n\n')
        fp.write('WhoIs results: \n\n' + whoIsInfo[i] + '\n\n')
        fp.write('DNS results: ' + dnsInfo[i] + '\n\n')
        fp.write('Server fingerprint: ' + fingerprints[i] + '\n\n')
        strVersion = getStringVersion(geolocation[i])
        fp.write('Geolocation results: \n\n' + strVersion)
        fp.write('\n\n---------------------------------------------------')
    fp.close()


def createDBFile(urls, whoIsInfo, dnsInfo, fingerprints, geolocation):
    dbConn = setUpDataBase()

    for i in range(len(urls)):
        strVersion = getStringVersion(geolocation[i])
        data = (urls[i], whoIsInfo[i], dnsInfo[i], fingerprints[i], strVersion)
        dbConn.execute('insert into analysis values (?, ?, ?, ?, ?)', data)
        dbConn.commit()

    dbConn.close()

def setUpDataBase():
    try:
        conn = sqlite3.connect(r'./analysis.db')
        conn.execute('CREATE TABLE IF NOT EXISTS analysis ( \
                        url text NOT  NULL, \
                        whois text NOT NULL, \
                        dns text NOT NULL, \
                        fingerprint text NOT NULL, \
                        geolocation text NOT NULL);')
        return conn
    except Exception as e:
        print('Unable to create SQLite file!', e)
        exit(0)

def createKMLFile(urls, geolocation):
    kml = simplekml.Kml()
    for i in range(len(urls)):
        location = (geolocation[i]['longitude'], geolocation[i]['latitude'])
        kml.newpoint(name=urls[i], coords=[location])
    kml.save('output.kml')

if __name__ == '__main__':
    main()
