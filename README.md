# ct-aws-python-saml

This is an example solution that uses SAML and CloudFront signed cookies to control access to static content in an S3 bucket.

It answers this question that the Cloud Team at Cornell is sometimes asked: 

> "How can I gate access to a static S3 website using Cornell identities?"

## Architecture

![architecture diagram](./docs/images/architecture.png)

## Deployment

### Deployment Steps

1. Clone this git repo to your workspace.
1. Gather prerequisite information and inputs:
   1. See [Prerequisites and Inputs](#prerequisites-and-inputs)
   1. Determine the DNS names your solution will use. 
   1. Create or identify ACM certificates required for the deployment.
   1. Get your hands on a CloudFront key pair for your AWS account and create a secret in the AWS Secrets Manager. See [CloudFront Signing Key](#cloudfront-signing-key).
1. Edit `template.yaml` to replace the default values for each parameter with those that you determined above.
1. Deploy the SAM template by one of three methods:
   - SAM CLI: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-deploy.html
   - AWS CLI: https://docs.aws.amazon.com/cli/latest/reference/cloudformation/deploy/index.html
   - AWS Cloud9: https://docs.aws.amazon.com/cloud9/latest/user-guide/lambda-functions.html 
   (Note that complete deployment time and subsequent updates will take 10-20 minutes because of the CloudFront distribution that is involved.)
   These methods all include a mechanism to upload the source code for the Lambda Function.
1. Deploy sample static files to S3:
   1. Check the output of the template (in CloudFormation) for `SyncCommand`, which is an AWS CLI command to sync static files from this repo to the content bucket. 
   1. Move to the root directory of this repo, and execute the `SyncCommand`. For example:
      ```
      $ aws s3 sync static-content/ s3://cloud9-pea1-python-saml-sitebucket-jvsng1tqexmu
      ```
1. Create a CNAME from `CloudFrontDNSNameParam` to `LocalDNSNameParam`. 
   - If `CloudFrontDNSNameParam` is a `cornell.edu` name, you will need to create this CNAME in Cornell DNSDB.
   - If `CloudFrontDNSNameParam` is in a domain hosted by AWS Route 53, do it there.
1. (Optional) Request that your deployment be integrated with Cornell Shibboleth. This is optional because the default deployment provides a `/cookies` URL that provides the same cookies as if your client got authorized via a SAML assertion. See [Configuring Shibboleth IdP](#configuring-shibboleth-idp).
1. Try out your deployment at `https://[CloudFrontDNSNameParam]/` 

#### TROUBLESHOOTING DEPLOYMENT

##### `PythonSAMLAPIDNSBase` fails to create in CloudFormation stack.

This situation may happen because CloudFormation tries to create `PythonSAMLAPIDNSBase` before the API stage `default` is fully created. If this happens, rerun the CloudFormation template, but this time with the `PythonSAMLAPIDNSBase` resource commented out. Once that is successful, uncomment the `PythonSAMLAPIDNSBase` and update the CloudFormation stack.

##### "CloudWatch logs role ARN must be set in account settings to enable logging"

In order to log to CloudWatch, API Gateway must be provided with a role ARN to use for that logging. This needs to be configured in API Gateway once for each region. See https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#set-up-access-logging-permissions.

### Prerequisites and Inputs

**`CloudFrontDNSNameParam`**
- The DNS name that is the user front door for the solution. This should be a CNAME to `LocalDNSNameParam`.
- Example: `shib-testbed.aws.cucloud.net`

**`CloudFrontCertificateIdParam`**
- The Id (not the full ARN) of the ACM certificate for the user front door (`CloudFrontDNSNameParam`). Must exist locally in the deployment region and AWS account.
- Example: `ef4bb1f2-e10f-4419-99a4-3d78b9cf319d` (*.aws.cucloud.net)
  
**`LocalDNSNameParam`**
- The DNS name of the deployment in the Route53 hosted zone controlled in the current AWS account. This allows for the deployment to be made in an AWS account that does not host the `CloudFrontDNSNameParam` CNAME in its own Route53 hosted zone. This name is not visible to end users.
- Example: `shib-testbed.cs.cucloud.net`

**`LocalHostedZoneNameParam`**
- The full name (including `.` at the end) of the Route53 hosted zone controlled in the current AWS account. This hosted zone should contain both the `LocalDNSNameParam` and the `APIGatewayDNSNameParam`
- Example: `cs.cucloud.net.`

**`APIGatewayDNSNameParam`**
- The DNS name to use for the API Gateway endpoint. This name is not visible to end users.
- Example: `shib-python.cs.cucloud.net`

**`APIGatewayCertificateIdParam`**
- The Id (not the full ARN) of the ACM certificate for the local API Gateway DNS name (`APIGatewayDNSNameParam`). Must exist locally in the deployment region and AWS account.
- Example: `9d434082-50a4-4553-a34a-91d2386db7e8` (*.cs.cucloud.net)

**`AllowedRoleArnsParam`**
- A string comprosed of a list of IAM Role ARNs in JSON array format. Each of the IAM Roles should have trust relationships established with the SAML IdP and work with standard SAML-enabled AWS console login. (Be careful with the format of this value. It must be a string representation of a parseable JSON array. It must be enclosed by quotes.)
- Anyone with privileges to assume any of these roles will be allowed to access the private content of the site.
- Example: `'["arn:aws:iam::012345678901:role/shib-admin","arn:aws:iam::012345678901:role/shib-cs"]'`
- Example: `'[]'` (empty list)

**`AllowedNetIDsParam`**
- A string comprised of a list of Cornell NetIds in JSON array format. (Be careful with the format of this value. It must be a string representation of a parseable JSON array. It must be enclosed by quotes.)
- Anyone with these NetIds will be allowed to access the private content of this site.
- Example: `'["abc123","xzy789"]'`
- Example: `'[]'` (empty list)

**`SamlIdpHostNameParam`**
- The SAML Identity Provider host name. This example is specifically configured to use the URLs of the test or production Shibboleth SAML IdP at Cornell.
- Example: `shibidp-test.cit.cornell.edu`
- Example: `shibidp.cit.cornell.edu`

**`SamlIdpX509CertificateParam`**
- The public X509 certificate of the SAML IdP. 
- This certificate can be found in the IdP metadata at:
  - https://shibidp-test.cit.cornell.edu/idp/shibboleth
  - https://shibidp.cit.cornell.edu/idp/shibboleth
- Example: `MIIDXDCCAkSgAwIBAgIVAMKCR8IGXIOzO/yLt6e4sd7OMLgEMA0GCSqGSIb...Wm7XIe8qtqo`

**`SigningKeySecretsManagerNameParam`**
- The name of the CloudFront signing key stored in the AWS Secrets Manager. See this document for more information about this signing key.
- Example: `/my-signing-key`

### CloudFront Signing Key

This deployment uses a CloudFront Key Pair to sign cookies that allow your users to access private content through CloudFront. A CloudFront Key Pairs can be managed only by the root account of an AWS account. If you the CIT Cloud Team manages the root credentials for your AWS account, please submit a request to cloud-support@cornell.edu to have a CloudFront Key Pair created.

AWS documentation about creating CloudFront key pairs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs

Creating this key pair and storing it in Secrets Manager is a one-time process, so it has not be automated. See AWS Secrets Manager documentation about creating secrets: https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_create-basic-secret.html

Your secret should have multiple key-value pairs and should be named as follows:
- `access-key-id` - The access key ID of the CloudFront key pair.
- `private-key-id` - The RSA private key text of the key pair
- `public-key` - The public half of the keypair; technically this isn't required for this deployment, but it seems like a good idea to keep it around.

The plaint text of your entire Secrets Manager secret should look something like this:
```
{
  "private-key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIB......cYAQOQ=\n-----END RSA PRIVATE KEY-----\n",
  "public-key": "-----BEGIN PUBLIC KEY-----\nMIIBIjA.....IDAQAB\n-----END PUBLIC KEY-----\n",
  "access-key-id": "APKXXXXXXXXXXXXXXXXX"
}
```
Note that the plaintext representation of the keys will have new lines represented as `\n`.

# Details

## URLs Handled by API Gateway and Lambda Python Function

If `CloudFrontDNSNameParam` is `shib-testbed.aws.cucloud.net` then requests for URLsare routed to the Lambda Function except those that match:
- `https://shib-testbed.aws.cucloud.net/public/*` - All content at this location is public.
- `https://shib-testbed.aws.cucloud.net/private/*` - Without appropriate authorization and CloudFront cookies, clients cannot access any content under `/private/`.

The Lambda Function handles the following requests specifically:
- `POST` to `https://shib-testbed.aws.cucloud.net/saml/consume` - This is the URL where Shibboleth directs client browsers after the login process is complete. The request body will contain `SAMLResponse` and optionally `RelayState`.

  The Lambda Function will validate the SAML assertion and decide if the client is authorized to see the private content of the deployment. If the client is authorized, the response will contain signed cookies to allow access to any URL matching this pattern:
  ```
  https://shib-testbed.aws.cucloud.net/private/*.html
  ```
- `GET` to `https://shib-testbed.aws.cucloud.net/saml/test` - This shows a simple form for pasting in a base64-encoded (but NOT URL-encoded) `SAMLResponse` and `RelayState`. Submitting this form will `POST` to `/saml/consume` to simulate getting a SAML response from the SAML IdP. This can be used to test SAML responses and ensure that old responses and manually altered responses are not processed as valid.
- `GET` to `https://shib-testbed.aws.cucloud.net/delete-cookies` - This request will trigger the Lambda Function to respond with a request that the browser delete CloudFront-related cookies. This effectively de-authorizes a client.
- `GET` to `https://shib-testbed.aws.cucloud.net/cookies` - A request to this URL will automatically provide signed cookies for accessing the private content. It would **NOT** be provided or used in a real deployment, but is useful for testing and debugging. Functionally, it forces the system to consider the client authorized, and provides the same signed cookies that are provided when the client successfully completed the SAML SSO process.
- `GET` to `https://shib-testbed.aws.cucloud.net/index.html` - This will return a simple page with links on it to exercise the deployment.
- `GET` to `https://shib-testbed.aws.cucloud.net/` - This will return the same response as `https://shib-testbed.aws.cucloud.net/index.html`
- `GET` to `https://shib-testbed.aws.cucloud.net/[anything else]` - This will redirect the client to `https://shib-testbed.aws.cucloud.net/public/index.html`

## Authorization Criteria

When handling a SAML reponse (at `/saml/consume`) the Lambda function processes the SAML assertion to determine whether the client is authorized to see the private content. If so, it provides a set of signed CloudFront cookies to the client. If not, no cookies are provided.

There are two ways a client can be considered authorized:

- The SAML assertion includes a Role configured in the list in `AllowedRoleArnsParam`.

- The identity information included in the SAML assertion includes a Cornell NetID contained in the list in `AllowedNetIDsParam`.

## Configuring Shibboleth IdP

The Cornell CIT Identity Management team manages configuration of Cornell's Shibboleth deployments (test and production). If you wish to deploy this solution and integrate it with Cornell Shibboleth, you will need to request that Identity Management configure your deployment as an SAML Service Provider.

You will need to provide the following information:
- The exact URL that your users should be directed to after their Shibboleth athentication is successful. For this deployment, the URL will be `https://[CloudFrontDNSNameParam]/saml/consume`. In our example deployment this value is `https://shib-testbed.aws.cucloud.net/saml/consume`.
- The SAML Service Provider id. This will be always be `urn:amazon:webservices`. The reason for this is that we are leveraging the existing Shibboleth configuration setup for Cornell AWS users to use Cornell Two-step Login to access the AWS Console.

## CloudFront Signed Cookies and Access Policy

The CloudFront cookies provided to authorized users include the following criteria:
- URL of requested content must match this pattern: `https://[CloudFrontDNSNameParam]/private/*.html`. Thuse only files with `.html` extensions are allowed. In most real situations, you'd probably want this pattern to be ``https://[CloudFrontDNSNameParam]/private/*`. This example shows, there you do have flexibility on what patterns you want to allow.
- The IPv4 address of the authorized client is included in the access policy, so the cookies cannot be used by a client at a different IPv4 address.
- Cookies are valid for 60 minutes, effectively giving a 60 minute "session" length. This limit is implemented within the signed cookies and is different from the expiration time of the cookies themselves.

Each of these specifics can be fairly easily modified in the Lambda Function code.

## Layer Info

The main Python libraries required are [cryptography](https://pypi.org/project/cryptography/) and [python3-saml](https://pypi.org/project/python3-saml/).

The layer contents have been created and can be found at https://s3.amazonaws.com/public.cloud.cit.cornell.edu/lambda/layers/ct-aws-python-saml/python36-onelogin-saml-2019-05-24.zip

Unless you are making your own custom layer because you need different libraries or different library versions, you do not need to worry additional layer details.

### Layout of Lambda Layer

- lib/
  - libffi-ae16d830.so.6.0.4
  - libxmlsec1-openssl.so -> libxmlsec1-openssl.so.1.2.20
  - libxmlsec1-openssl.so.1 -> libxmlsec1-openssl.so.1.2.20
  - libxmlsec1-openssl.so.1.2.20
  - libxmlsec1.so -> libxmlsec1.so.1.2.20
  - libxmlsec1.so.1 -> libxmlsec1.so.1.2.20
  - libxmlsec1.so.1.2.20
- python/
  - \_cffi\_backend.cpython-36m-x86_64-linux-gnu.so
  - asn1crypto/
  - cffi/
  - cryptography/
  - defusedxml/
  - isodate/
  - lxml/
  - onelogin/
  - xmlsec.cpython-36m-x86_64-linux-gnu.so

### Creating the Lambda Layer

1. Start with a clean Python 3.6 environment
1. Install the supporting libraries 
1. Copy the library `.so` files and python module directories into a clean directory structure as outlined above. 
1. Zip up the contents of the directory structure. DON'T include a top level directory in the zip file. `lib` and `python` need to at the top level of the zip file.

#### Installing cryptography

```
pip3 install cryptography
```

#### Installing python3-saml

This library requires xmlsec, which has good install information here: https://github.com/mehcode/python-xmlsec.

**Installing on Centos/Amazon Linux**
```
yum install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel

pip3 install defusedxml --user
pip3 install isodate --user
pip3 install xmlsec --user
pip3 install python3-saml --user
pip3 install lxml --user
```

## Improvements

- Set/refine HTTP response headers for managing caching of static content. The current CloudFront configuration sets TTL for most responses to 0, but nothing has been done beyond that has been done or explored.
- Consider setting separate signed cookies for different private URL scopes. e.g., www.example.com/private-1 has one signed cookie and www.example.com/private-2 has another. This may help get around the policy limitation of CloudFront signed cookies, which allows you only one wild-carded string e.g. www.example.com/private/*.html in the custom policy for your signed cookie.
