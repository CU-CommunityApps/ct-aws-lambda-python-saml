import base64
import json
import urllib.parse
import time
import boto3
import os
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

SAML_IDP_X509_CERT_DEFAULT = "MIIDXDCCAkSgAwIBAgIVAMKCR8IGXIOzO/yLt6e4sd7OMLgEMA0GCSqGSIb3DQEBBQUAMCcxJTAjBgNVBAMTHHNoaWJpZHAtdGVzdC5jaXQuY29ybmVsbC5lZHUwHhcNMTIwNjA3MTg0NjIyWhcNMzIwNjA3MTg0NjIyWjAnMSUwIwYDVQQDExxzaGliaWRwLXRlc3QuY2l0LmNvcm5lbGwuZWR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkhlf9EP399mqnBtGmPG9Vqu79Af2NZhhsT+LTMA1uhPZYv4RX/E4VD+Iqce/EUP1ndPkGEwBnhrRT2ZegDpCmgo+EcED8cAh9AbwFTTitmBjxvErtJnS0ZBfMCLDcgOV1zM6bT5fF9SAIm0ZVSaeyQbNDwVDdwsBQHjAdg5vLd5VeYH9MI6enzdgBtPNSrEt3qZtCWl7ev8YQlWF3vZ+EoyDrWPZSOWzgR31QBs7mz13ABSveIri68FgNth9ylgFS7VNUlAp6xx6BRnMgL1QzVMZ5F4PbSRDp3UBoS6PMHd+WFenJWPPh6ShMyrInrJ4QAPfKC77tJW+GUXl4T4DqQIDAQABo38wfTBcBgNVHREEVTBTghxzaGliaWRwLXRlc3QuY2l0LmNvcm5lbGwuZWR1hjNodHRwczovL3NoaWJpZHAtdGVzdC5jaXQuY29ybmVsbC5lZHUvaWRwL3NoaWJib2xldGgwHQYDVR0OBBYEFF9RADnmBsO50hD8T+MUFqIgWAOxMA0GCSqGSIb3DQEBBQUAA4IBAQBqYpfdK4XAYE56sYmq/vUKOSBcbO2Uy3R7oTGrDKxrZI7xC1jchaaTW6BXtg6wzTSn8Jo2M0gvQrWyxZgQDrXGaL2TaPf5WjOWt/SsuJ+IShofS6ZWLkPCnrR0Ag9PwU58szw2jjUE4eJyv/dLDzhDHJ0EGastgSzRh1r3v2w8BYz1RHvjwESPB2HTgV1iuHwaIjaJxN39XyS6ZQzBj6sZ6Lem1R39zXmEvtVfCk9qgSKnbYulrrkIBzxllB34TUTKFs+Nz1j/sg2gj6Q5u9uW6mSm66mqn2E53r2CNHPTzWGwom5Mi9Z/DtOb2L/5jjxhFvCKxnEbIWm7XIe8qtqo"
SAML_IDP_HOSTNAME = os.environ.get('SAML_IDP_HOSTNAME', 'shibidp-test.cit.cornell.edu')
SAML_IDP_X509_CERT = os.environ.get('SAML_IDP_X509_CERT', SAML_IDP_X509_CERT_DEFAULT)
SAML_SP_HOSTNAME = os.environ.get('SAML_SP_HOSTNAME', 'shib-testbed.aws.cucloud.net')
SAML_SP_INTERNAL_PATH_PREFIX  = os.environ.get('SAML_SP_INTERNAL_PATH_PREFIX', '/python')
SAML_SP_ROOT_URL = 'https://'+ SAML_SP_HOSTNAME

SECRETS_MANAGER_SECRET_NAME = os.environ.get('SECRETS_MANAGER_SECRET_NAME', 'cloudfront-signing-key-secret')

# Value should be a JSON array of role ARNs
EXAMPLE_TARGET_ROLE_ARNS = '[]'
TARGET_ROLE_ARNS = json.loads(os.environ.get('TARGET_ROLE_ARNS', EXAMPLE_TARGET_ROLE_ARNS))

EXAMPLE_TARGET_NETIDS = '[]'
TARGET_NETIDS = json.loads(os.environ.get('EXAMPLE_TARGET_NETIDS', EXAMPLE_TARGET_NETIDS))

SAML_ATTRIBUTE_NETID = 'urn:oid:0.9.2342.19200300.100.1.1'

def get_x_forwarded_for(event):
    return event['headers'].get('X-Forwarded-For', '')

def get_real_client_ip(event):
    return get_x_forwarded_for(event).split(',')[0]

def get_index_html(event):
    ips = get_x_forwarded_for(event)
    client_ip = get_real_client_ip(event)
    return f'''<html>
<body>
  <h1>Python Lambda</h1>
  <p>X-Forwarded-For: {ips}</p>
  <p>Client IP: {client_ip}</p>
  <p><a href='cookies'>Generate Cookies</a></p>
  <p><a href='delete-cookies'>Delete Cookies</a></p>
  <p><a href='/public/index.html'>Unsecured File</a></p>
  <p><a href='/private/index.html'>Secured File 1 - should work with cookies</a></p>
  <p><a href='/private/more.html'>Secured File 2 - should works with cookies</a></p>
  <p><a href='/private/index.txt'>Secured File 3 - won't work because it is .txt</a></p>
  <p>
    <a href='https://{SAML_IDP_HOSTNAME}/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices&shire=https://{SAML_SP_HOSTNAME}/saml/consume'>
      Trigger Unsolicited SAML Request
    </a>
  </p>
  <p>
    <a href='https://{SAML_IDP_HOSTNAME}/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices&shire=https://{SAML_SP_HOSTNAME}/saml/consume&target=https://{SAML_SP_HOSTNAME}/'>
      Trigger Unsolicited SAML Request with Target
    </a>
  </p>
</body>
</html>
'''

def get_not_authorized_html(event):
    return f'''<html>
<body>
  <p>You are not authorized to access this content. Your session may have timed out. If so, please login again.</p>
  <p id="demo"></p>
  <p><a id="login-link" href='https://{SAML_IDP_HOSTNAME}/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices&shire=https://{SAML_SP_HOSTNAME}/saml/consume&target=https://{SAML_SP_HOSTNAME}/'>Login to refresh your session.</a></p>
  <script>
    document.getElementById("login-link").href = "https://{SAML_IDP_HOSTNAME}/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices&shire=https://{SAML_SP_HOSTNAME}/saml/consume&target=" + window.location.href;
    document.getElementById("demo").innerHTML = "Target = " + window.location.href;
  </script>
</body>
</html>
'''

def get_set_cookie_value(name, value, domain=SAML_SP_HOSTNAME, path='/'):
    return f'{name}={value}; domain={domain}; path={path}; secure; HttpOnly; SameSite=strict'

def get_del_cookie_value(name, domain=SAML_SP_HOSTNAME, path='/'):
    return f'{name}=; domain={domain}; path={path}; max-age=0; expires=Thu, 01 Jan 1970 00:00:00 -0000; secure; HttpOnly; SameSite=strict'

def set_cookie(name, value, cookies_hash={}, domain=SAML_SP_HOSTNAME, path='/'):
    cookies_hash[name] = get_set_cookie_value(name, value, domain, path)
    return cookies_hash

def del_cookie(name, cookies_hash={}, domain=SAML_SP_HOSTNAME, path='/'):
    cookies_hash[name] = get_del_cookie_value(name, domain, path)
    return cookies_hash

def respond_html(response, cookies_hash={}):
    return {
        'statusCode': '200',
        'body': response,
        'headers': {
            'Content-Type': 'text/html'
        },
        'multiValueHeaders': {
            'Set-Cookie' : list(cookies_hash.values())
        }
    }

def response_redirect(url, cookies_hash={}):
    return {
        'statusCode': '302',
        'body': None,
        'headers': {
            'Content-Type': 'text/html',
            'Location': url
        },
        'multiValueHeaders': {
            'Set-Cookie' : list(cookies_hash.values())
        }
    }

def response_get_not_authorized_html(response):
    return {
        'statusCode': '401',
        'body': response,
        'headers': {
            'Content-Type': 'text/html'
        },
    }

def saml_consume(event, cookies):
    body = event.get('body', "")
    body_data = urllib.parse.parse_qs(body)
    relay_state = body_data.get('RelayState', "")
    if relay_state:
        relay_state = relay_state[0]
    raw_saml_response = body_data.get('SAMLResponse', None)
    assert raw_saml_response, "SAMLResponse not present in POST data!"
    raw_saml_response = raw_saml_response[0]
    raw_saml_response = urllib.parse.unquote(raw_saml_response)

    # filename = "./onelogin-saml.settings.json" # The custom_settings.json contains a
    # json_data_file = open(filename, 'r')       # settings_data dict.
    # settings_data = json.load(json_data_file)
    # json_data_file.close()
    # idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote('https://' + SAML_IDP_HOSTNAME + '/idp/shibboleth')
    # settings_data['idp'] = idp_data['idp']
    settings = OneLogin_Saml2_Settings(get_onelogin_saml_settings())

    processed_saml_response = OneLogin_Saml2_Response(settings, raw_saml_response)

    # This will raise an exception if not a valid SAML response
    processed_saml_response.check_status()

    attributes = processed_saml_response.get_attributes()
    roles = attributes["https://aws.amazon.com/SAML/Attributes/Role"]
    roles_arns = []
    roles_str = ""
    for r in roles:
        r1 = r.split(',')[1]
        roles_arns.append(r1)
        roles_str += r1 + "\n"

    intersection = set(roles_arns) & set(TARGET_ROLE_ARNS)
    authorized_via_role = bool(intersection)

    netid = attributes[SAML_ATTRIBUTE_NETID][0]
    authorized_via_netid = netid in TARGET_NETIDS

    authorized = authorized_via_netid or authorized_via_role

    html = f'''<html>
<body><h1>Consume Saml</h1>
<pre>
Requested url: { relay_state }
Authorized: { authorized }
Authorized via role: { authorized_via_role }
Authorized via netid: { authorized_via_netid }
audiences:  { processed_saml_response.get_audiences() }
get_issuers: { processed_saml_response.get_issuers() }
get_nameid: { processed_saml_response.get_nameid() }
netid: { netid }
email_address: { attributes["urn:oid:0.9.2342.19200300.100.1.3"][0] }
Full name: { attributes["urn:oid:2.5.4.3"][0]}
Display name: { attributes["urn:oid:2.16.840.1.113730.3.1.241"][0]}
Given name: { attributes["urn:oid:2.5.4.42"][0]}
Surname: { attributes["urn:oid:2.5.4.4"][0]}
roles: { roles_str }
</pre>
</body></html>
'''
    if not authorized:
        return response_get_not_authorized_html(html)

    cookies = get_signed_cookies(get_real_client_ip(event))

    if relay_state:
        return response_redirect(relay_state, cookies)

    return respond_html(html, cookies)

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))

    path = event['path']
    print("path:" + path)
    print("method: " + event['httpMethod'])
    print("x-forwarded-for: " + get_x_forwarded_for(event))
    print("real client ip: " + get_real_client_ip(event))
    print("queryStringParameters:" + json.dumps(event.get('queryStringParameters', '')))
    print("multiValueQueryStringParameters:" + json.dumps(event.get('multiValueQueryStringParameters', '')))

    cookies = {}
    if path == SAML_SP_INTERNAL_PATH_PREFIX  + '/index.html':
        response = respond_html(get_index_html(event), cookies)
    elif path == SAML_SP_INTERNAL_PATH_PREFIX  + '/not-authorized':
        response = respond_html(get_not_authorized_html(event), cookies)
    elif path == SAML_SP_INTERNAL_PATH_PREFIX  + '/delete-cookies':
        del_cookie('CloudFront-Policy', cookies)
        del_cookie('CloudFront-Signature', cookies)
        del_cookie('CloudFront-Key-Pair-Id', cookies)
        del_cookie('CloudFront-Expires', cookies)
        response = response_redirect(SAML_SP_ROOT_URL, cookies)
    elif path == SAML_SP_INTERNAL_PATH_PREFIX  + '/cookies':
        cookies = get_signed_cookies(get_real_client_ip(event))
        response = response_redirect(SAML_SP_ROOT_URL, cookies)
    elif path == SAML_SP_INTERNAL_PATH_PREFIX  + '/saml/consume':
        response = saml_consume(event, cookies)
    else:
        response = response_redirect(SAML_SP_ROOT_URL+'/public/index.html', cookies)

    print("Response: " + json.dumps(response, indent=2))
    return response


def get_onelogin_saml_settings():
    return {
        'strict': True,
        'debug': True,
        'sp': {
            'entityId': "urn:amazon:webservices",
            'assertionConsumerService': {
                'url': "https://" + SAML_SP_HOSTNAME + "/saml/consume",
                'binding': "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            'NameIDFormat': "urn:mace:shibboleth:1.0:nameIdentifier"
        },
        'idp': {
            'entityId': "https://" + SAML_IDP_HOSTNAME + "/idp/shibboleth",
            'singleSignOnService': {
                "url": "https://" + SAML_IDP_HOSTNAME + "/idp/profile/SAML2/Redirect/SSO",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            'x509cert': SAML_IDP_X509_CERT
        },
    }

###############################################################################
## Signed Cookies
###############################################################################

def get_signed_cookies(client_ip):
    key_pair_info = get_cloud_front_key()
    # print("access key id: " + key_pair_info['access-key-id'])
    key_id = key_pair_info['access-key-id']
    key_contents = key_pair_info['private-key'].encode() # convert to bytes
    url = 'https://' + SAML_SP_HOSTNAME + '/private/*.html'
    signed_hash = generate_signed_cookies(url, key_id, key_contents, client_ip)
    cookies = {}
    for c in signed_hash:
        set_cookie(c, signed_hash[c], cookies)
    return cookies

def get_cloud_front_key():
    print("USING SECRET NAME: [{}]".format(SECRETS_MANAGER_SECRET_NAME))
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager'
    )
    try:
        response = client.get_secret_value(
            SecretId=SECRETS_MANAGER_SECRET_NAME
        )
    except ClientError as e:
        print(e)
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in response:
            return json.loads(response['SecretString'])
    print("ERROR - Unable to retrieve secret, or secret not structured as expected.")
    return ""

###############################################################################
# Creating signed cookies.
# from https://gist.github.com/mjohnsullivan/31064b04707923f82484c54981e4749e
###############################################################################

def _replace_unsupported_chars(some_str):
    """Replace unsupported chars: '+=/' with '-_~'"""
    return some_str.replace("+", "-") \
        .replace("=", "_") \
        .replace("/", "~")

def _in_an_hour():
    """Returns a UTC POSIX timestamp for one hour in the future"""
    return int(time.time()) + (60*60)

def rsa_signer(message, key):
    """
    Based on https://boto3.readthedocs.io/en/latest/reference/services/cloudfront.html#examples
    """
    private_key = serialization.load_pem_private_key(
        key,
        password=None,
        backend=default_backend()
    )
    signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1())
    signer.update(message)
    return signer.finalize()


def generate_policy_cookie(url, client_ip):
    """Returns a tuple: (policy json, policy base64)"""

    policy_dict = {
        "Statement": [
            {
                "Resource": url,
                "Condition": {
                    "IpAddress": {"AWS:SourceIp" : client_ip + "/32"},
                    "DateLessThan": {"AWS:EpochTime":  _in_an_hour()}
                }
            }
        ]
    }

    # Using separators=(',', ':') removes seperator whitespace
    policy_json = json.dumps(policy_dict, separators=(",", ":"))

    policy_64 = str(base64.b64encode(policy_json.encode("utf-8")), "utf-8")
    policy_64 = _replace_unsupported_chars(policy_64)
    return policy_json, policy_64


def generate_signature(policy, key):
    """Creates a signature for the policy from the key, returning a string"""
    sig_bytes = rsa_signer(policy.encode("utf-8"), key)
    sig_64 = _replace_unsupported_chars(str(base64.b64encode(sig_bytes), "utf-8"))
    return sig_64

def generate_cookies(policy, signature, cloudfront_id):
    """Returns a dictionary for cookie values in the form 'COOKIE NAME': 'COOKIE VALUE'"""
    return {
        "CloudFront-Policy": policy,
        "CloudFront-Signature": signature,
        "CloudFront-Key-Pair-Id": cloudfront_id
    }

def generate_signed_cookies(url, cloudfront_id, key, client_ip):
    policy_json, policy_64 = generate_policy_cookie(url, client_ip)
    signature = generate_signature(policy_json, key)
    return generate_cookies(policy_64, signature, cloudfront_id)
