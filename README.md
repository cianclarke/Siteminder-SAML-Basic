# FeedHenry Hello World MBaaS Server

This is a blank 'hello world' FeedHenry MBaaS. Use it as a starting point for building your APIs. 

# Group SAML API

# login [/saml/login]

SAML Login endpoint.

## login [POST] 

Login endpoint.

+ Request (application/json)
    + Body
            {
              "username" : "RHMobilityPoc1",
              "password" : "Password.123"
            }

+ Response 200 (application/json)
    + Body
            {
              "data": "saml assertion goes here"
            }
