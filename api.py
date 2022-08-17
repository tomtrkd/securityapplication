from os import POSIX_FADV_NOREUSE
import flask
from flask import request, jsonify
from flask import Flask
from flask import Response
from flask_cors import CORS
from flask import Response
from urllib.parse import urlparse
import pickle
from tinydb import TinyDB, Query
from pysafebrowsing import SafeBrowsing
import api_keys

app = Flask(__name__)
#cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

CORS(app)

sb_lookup = SafeBrowsing(api_keys.g_sb_key)

def cert_type_check(domain):
    try:
        test_data = get_certificate(domain, 443)

        try:
            cert_pol = test_data.cert.extensions.get_extension_for_class(x509.CertificatePolicies)
            cert_pol = str(cert_pol)

            if DV in cert_pol:
                cert_type = "dv"

            elif EV in cert_pol:
                cert_type = "ev"

            elif OV in cert_pol:
                cert_type = "ov"

            else:
                cert_type = "not_found"

        except:

            cert_type = "not_found"

    except:
        cert_type = "not_found"

    return cert_type


def check_https(url):
    https_check = url.startswith("https")
    return https_check

def stand_url(url):     
    url = url.lower()
    return url

def knownsafe_check(domain):     
    if domain in safe_domains:
        return True
    elif domain not in safe_domains:
        return False


def baddomain_check(domain):     
    if domain in bad_domains:
        return True
    elif domain not in bad_domains:
        return False

def extract_domain(url):
    
    domain = urlparse(url).netloc
    www_check = domain.startswith("www.")
    if www_check == True:
        domain = domain.removeprefix("www.")
    else:
        pass
    return domain

db = TinyDB('db.json')
data = Query()

file_in = open("top1m.pickle","rb")
top1m = pickle.load(file_in)
file_in.close()

file_in = open("known_safe.pickle","rb")
known_safe = pickle.load(file_in)
file_in.close()

file_in = open("top50k.pickle","rb")
top50k = pickle.load(file_in)
file_in.close()

file_in = open("bad_domains.pickle","rb")
bad_domains = pickle.load(file_in)
file_in.close()

app = flask.Flask(__name__)
app.config["DEBUG"] = False

@app.route('/', methods=['GET'])
def home():
    return '''<h1>Safe Site API</h1>
<p>A prototype API for checking if a site is safe.</p>'''

@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404

@app.route('/api/v1/basic', methods=['GET'])
def api_basic():
    query_parameters = request.args 

    if 'url' in request.args:
        url = request.args['url']
    else:
        return "Error: No url field provided. Please specify an url."

    url = stand_url(query_parameters.get('url'))

    domain = extract_domain(url)
    if domain in known_safe:


        test_result = {
        "Result": "Pass",
        "Reason": "The " + domain + " is known to be safe barring any unforseen hacks.",
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }   
        return test_result

        

    # quick check to see if we know about the domain in our combined threat intel
    bd_check = baddomain_check(domain)

    if bd_check == True:
        test_result = {
        "Result": "Fail",
        "Reason": "The " + domain + " is not safe, our data indicated that it is likely malicoius",
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }   

        return test_result

    
    elif bd_check == False:
        pass 

    else:
        db.insert({'log': 'error', 'type': 'elif exception', 'url': url})
       
        return "sorry and error has occured we have logged it and will look into it"

    sb_data = sb_lookup.lookup_urls([url])
    sb_check = sb_data[url]["malicious"]

    if sb_check == True:


        test_result = {
        "Result": "Fail",
        "Reason": "The " + domain + " failed google safe browsing check",
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }   

        return test_result

    elif sb_check == False:
        pass
    else:
        db.insert({'log': 'error', 'type': 'elif exception', 'url': url})
       
        return "sorry and error has occured we have logged it and will look into it"
        

    #check to see if domain uses https
    https_check = check_https(url)

    if https_check == True:

        test_result = {
        "Result": "Pass",
        "Reason": "The " + domain + " is using HTTPS and therefore is safe to login or fill in forms/sbmit data",
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }   

        return test_result

    elif https_check == False:
    
        test_result = {
        "Result": "Fail",
        "Reason": "The " + domain + " is not using HTTPS and therefore is not safe to login or fill in forms/sbmit data",
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }   

        return test_result

    else:

        db.insert({'Error': 'else180', 'url': url})

       
        return "error"



@app.route('/api/v1/falsepos', methods=['GET'])
def api_falsepos():

    query_parameters = request.args 

    if 'url' in request.args:
        url = request.args['url']
    else:
        return "Error: No url field provided. Please specify an url."

    db.insert({'log': 'falsepos', 'url': url})
       
    return "Thank you we will look into the domain you submit to see if it safe"

@app.route('/api/v1/natonalsite', methods=['GET'])
def test_national():
    query_parameters = request.args 

    if 'url' in request.args:
        url = request.args['url']
    else:
        return "Error: No url field provided. Please specify an url."
    
    url = stand_url(query_parameters.get('url'))

    domain = extract_domain(url)

    if domain in known_safe:
        
        test_result = {
            "Result": "Pass",
            "Reason": "The " + domain + " is known to be safe barring any unforseen hacks.",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }
    
        return test_result


    # quick check to see if we know about the domain in our combined threat intel
    bd_check = baddomain_check(domain)

    if bd_check == True:


        test_result = {
            "Result": "Fail",
            "Reason": "The site " + domain + " is not safe, our data indicated tat it likely malicoius",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ",
        }
    
        return test_result

    
    elif bd_check == False:
        pass

    else:
        db.insert({'log': 'error', 'type': 'elif exception', 'url': url})
       
        return "sorry and error has occured we have logged it and will look into it"

    sb_data = sb_lookup.lookup_urls([url])
    sb_check = sb_data[url]["malicious"]

    if sb_check == True:
        return "The site " + domain + " failed google safe browsing check"
    elif sb_check == False:
        pass
    else:
        db.insert({'log': 'error', 'type': 'elif exception', 'url': url})
       
        return "sorry and error has occured we have logged it and will look into it"

    #check to see if domain uses https
    https_check = check_https(url)

    if https_check == True:
        pass

    elif https_check == False:

        test_result = {
            "Result": "Fail",
            "Reason": "is not using HTTPS and therefore is not safe to login or fill in forms/sbmit data",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong ", }
    
        return test_result

        #check to see if domain in top1m

    if domain in top1m: 
        pass

    elif domain not in top1m:

        test_result = {
            "Result": "Fail",
            "Reason": "The " + domain + " is not in the TOP 1M list of sites so is unlikely to be legitimate if it meant to be large national website site ",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
    
        return test_result

    ##insert tinydb search to check for record - at this point as all other checks are low recource requirments

    lookup = db.search(data.domain == domain)
    lookup_len = len(lookup)

    if lookup_len == 1:
        ## use data in lookup and to return

        return  lookup[0]

    elif lookup_len == 0:
        db.insert({'log': 'error', 'type': 'multi entry in db', 'url': url})
        pass
        

    else: 
        db.insert({'log': 'error', 'type': 'else in look up', 'url': url})
        pass

    ## carry on with check
    message = "This site is likely safe as all test back OK but you could always use https://urlscan.io/ for further conformation"

    test_result = {
        "Result": "Pass",
        "Reason": domain + " " + message,
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
    }
 
    return test_result


@app.route('/api/v1/major-int-natonalsite', methods=['GET'])
def major_national():
    query_parameters = request.args 

    if 'url' in request.args:
        url = request.args['url']
    else:
        return "Error: No url field provided. Please specify an url."
    
    url = stand_url(query_parameters.get('url'))

    domain = extract_domain(url)

    if domain in known_safe:

        test_result = {
            "Result": "Pass",
            "Reason": "The " + domain + " is known to be safe barring any unforseen hacks.",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
    
        return test_result


    # quick check to see if we know about the domain in our combined threat intel
    bd_check = baddomain_check(domain)

    if bd_check == True:

        test_result = {
            "Result": "Fail",
            "Reason": "The site " + domain + " is not safe, our data indicated tat it likely malicoius",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
    
        return test_result


    elif bd_check == False:
        pass

    else:
        db.insert({'log': 'error', 'type': 'elif exception', 'url': url})
       
        return "sorry and error has occured we have logged it and will look into it"

    sb_data = sb_lookup.lookup_urls([url])
    sb_check = sb_data[url]["malicious"]

    if sb_check == True:

        test_result = {
            "Result": "Fail",
            "Reason": "The site " + domain + " failed google safe browsing check",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
    
        return test_result

    elif sb_check == False:
        pass
    else:
        db.insert({'log': 'error', 'type': 'elif exception', 'url': url})
       
        return "sorry and error has occured we have logged it and will look into it"

    #check to see if domain uses https
    https_check = check_https(url)

    if https_check == True:
        pass

    elif https_check == False:

        test_result = {
            "Result": "Fail",
            "Reason": "The " + domain + " is not using HTTPS and therefore is not safe to login or fill in forms/sbmit data ",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
    
        return test_result

    #check to see if domain in top1m

    if domain in top50k: 
        pass

    elif domain not in top50k:

        test_result = {
            "Result": "Fail",
            "Reason": "The " + domain + " is not in the TOP 50k list of sites so is unlikely to be legitimate if it meant to be major national website site ",
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
    
        return test_result
         
    ##insert tinydb search to check for record - at this point as all other checks are low recource requirments

    lookup = db.search(data.domain == domain)
    lookup_len = len(lookup)

    if lookup_len == 1:
        ## use data in lookup and to return
        return lookup[0]

    elif lookup_len == 0:
        db.insert({'log': 'error', 'type': 'multi entry in db', 'url': url})
        pass
        

    else: 
        db.insert({'log': 'error', 'type': 'else in look up', 'url': url})
        pass

    cert_test = cert_type_check(domain)

    if cert_test == "dv" or cert_test == "not_found":
        message = "This site is likely not safe as it either using a basic certificate or we could not detect one but you could always use https://urlscan.io/ for further conformation"

        test_result = {
            "Result": "Fail",
            "Reason": domain + " " + message,
            "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
        }
        db.insert(test_result)
        return test_result

    elif cert_test == "ov" or cert_test == "ev":
        pass
    
    ## carry on with check
    message = "This site is likely safe as all test back OK but you could always use https://urlscan.io/ for further conformation"

    test_result = {
        "Result": "Pass",
        "Reason": domain + " " + message,
        "Feedback": "get request that contains details to submit feedback to report suspect false results if the user thinks the results are wrong "
    }
    db.insert(test_result)
    return test_result

app.run()
