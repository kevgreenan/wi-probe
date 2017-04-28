import sys
import getopt
import requests
import json
import shodan

####
#### GLOBAL VARIABLES
####

# Wigle
user = '' # conf
password = '' # conf
parameters = {'onlymine':'false','freenet':'false','paynet':'false','ssid':'ssid'}
url = 'https://api.wigle.net/api/v2/network/search'
ssid = ''
doSearch = 0

# Google
googleParameters = {'latlng':'latlng','key':'key'} # conf
gurl = 'https://maps.googleapis.com/maps/api/geocode/json'
coords = ''

# Shodan
shodanKey = shodan.Shodan('key') # conf
useShodan = 0

####
# Help
def usage():
    print
    print "#-------------------------------------------------------------------#"
    print "|                     WI-PROBE: SSID PROFILER                       |"
    print "#-------------------------------------------------------------------#"
    print
    print "#-------------------------------------------------------------------#"
    print "|                              USAGE:                               |"
    print "|                                                                   |"
    print "| -h, --help                                     Displays this page |"
    print "| -s, --shodan                                 Toggle Shodan search |"
    print "| -e, --essid                               Target ESSID (required) |"
    print "|                                                                   |"
    print "#-------------------------------------------------------------------#"
    print
    print "#-------------------------------------------------------------------#"
    print "|                            EXAMPLES:                              |"
    print "|                                                                   |"
    print "| wi-probe.py -e xfinitywifi                                        |"
    print "| wi-probe.py -s --essid MyWifi                                     |"
    print "|                                                                   |"
    print "#-------------------------------------------------------------------#"
    print
    sys.exit(0)

####
# Wigle functions
def setWigleData():
    parameters['ssid'] = ssid

def getWigleData():
    return requests.get(url, auth = (user, password), params = parameters)

def makeWigleRequest():
    global coords

    setWigleData()
    req = getWigleData()

    # LOOP FOR EACH WiGLE RESULT
    # pull coords from Wigle
    json_string = req.text
    parsed_json = json.loads(json_string)

    if parsed_json["success"] == 'true':
        end = parsed_json["resultCount"]
        for i in range(0, end):
            lat = str(parsed_json["results"][i]["trilat"])
            lon = str(parsed_json["results"][i]["trilong"])
            coords = lat + "," + lon

            # pull MAC from Wigle
            tmpMac = parsed_json["results"][i]["netid"]

            if useShodan == 1:
                mac = tmpMac
                #mac = 'FF:54:00:12:00:5c' # for debug; does not return IP
                getShodanData(mac)
            print ''

            makeGoogleRequest()
    else:
        print "ERROR: " + parsed_json["error"]

####
# Google functions
def setGoogleData():
    googleParameters['latlng'] = coords

def getGoogleData():
    return requests.get(gurl, params = googleParameters)

def makeGoogleRequest():
    setGoogleData()
    json_string = getGoogleData().text
    parsed_json = json.loads(json_string)
    addr = parsed_json["results"][0]["formatted_address"]
    print addr

####
# Shodan methods
def getShodanData(mac):
    query = 'mac:\"' + mac + '\"'
    try:
        result = shodanKey.search(query)
        message = ''
        noResults = "MAC " + mac + " not found in Shodan"
        # Loop through the matches and print each IP
        for service in result['matches']:
                message += service['ip_str']
                message += '\n'
        if message == '':
            print noResults
        else:
            # strip last return
            i = len(message) - 1
            message = message[0:i]
            print message
    except Exception as e:
        print 'Error: %s' % e
        sys.exit(1)

####
# Preconfiguration
def preconf():
    global user
    global password
    global googleParameters
    global shodanKey

    json_data=open("wi-probe.conf").read()
    data = json.loads(json_data)

    user = data["wigle_user"]
    password = data["wigle_password"]
    googleParameters["key"] = data["google_key"]
    shodanKey = shodan.Shodan(data["shodan_key"])

####
# ENTRY POINT
def main():
    global useShodan
    global ssid
    global doSearch

    if not len(sys.argv[1:]):
        usage()
    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hse:", ["help","shodan","essid"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-s", "--shodan"):
            useShodan = 1
        elif o in ("-e", "--essid"):
            ssid = a
            doSearch = 1
        else:
            assert False,"Unhandled Option"

    if doSearch == 1:
        preconf()
        makeWigleRequest()

if __name__=="__main__":main()
