var express = require('express');
var bodyParser = require('body-parser');
var cors = require('cors');
var xml2js = require('xml2js');
var parseString = xml2js.parseString;
var stripPrefix = xml2js.processors.stripPrefix;
var normalize = xml2js.processors.normalize;

function samlRoute() {
  var saml = new express.Router();
  saml.use(cors());
  saml.use(bodyParser());


  saml.all('/saml/consume', function(req, res){
    return res.json({ok : true});
  });
  
  saml.post('/saml/login', function(req, res){
    var request = require('request'),
    username = req.body.username,
    password = req.body.password,
    auth = {
      user : username,
      pass : password,
      sendImmediately : true
    };
    // Step 1 - request the AUTH_URL and get redirected
    request.get({
      url : process.env.SAML_URL,
      followRedirect : false,
      followAllRedirects : false,
      proxy : 'http://127.0.0.1:8080',
      jar : true,
      //auth : auth,
      headers : {
        'Cookie' : 'SMCHALLENGE=YES'
      }
    }, function(err, response){
      if (err || !response.headers || !response.headers.location){
        return res.status(500).json(err || 'No redirect found');
      }
      // Step 2 - follow the redirect, picking up cookies along the way as part of the 
      // Federation - Affwebservices basic auth challenge
      var newUrl = response.headers.location;
      request.get({
        url : newUrl,
        jar : true,
        proxy : 'http://127.0.0.1:8080',
      }, function(err, response){
        if (err){
          return res.status(500).json(err);
        }
        // Now that we've picked up all the cookies we need, this is the "money shot". 
        // A reply from this should give us our SAML response. 
        request.get({
          url : newUrl,
          jar : true,
          proxy : 'http://127.0.0.1:8080',
          auth : auth
        }, function(err, response, body){
          if (err){
            return res.status(500).json(err);
          }
          if (response.statusCode !== 200){
            return res.status(response.statusCode).end(body);
          }
          var samlBody = /value\s?=\s?"([a-zA-Z0-9+=\/\s]+)">/g,
          samlAssertion = samlBody.exec(response.body);
          if (!samlAssertion || samlAssertion.length !== 2){
            return res.status(401).json({ error : "No SAML assertion found in response" });
          }
          // take the regex'd result, the b64 string
          samlAssertion = samlAssertion[1];
          try{
            samlAssertion = new Buffer(samlAssertion, 'base64').toString();
          }catch(err){
            return res.status(401).json({error : "Error decoding base64 saml assertion"});
          }
          
          parseString(samlAssertion, { normalize : true, explicitArray : false, attrNameProcessors : [stripPrefix], tagNameProcessors : [stripPrefix, normalize]  }, function (err, samlAsJSON) {
            if (err){
              return res.status(500).json({ error : "Error parsing SAML response XML"});
            }
            var assertion = samlAsJSON && samlAsJSON.response && samlAsJSON.response.assertion || samlAsJSON;
            return res.json(assertion);
          });
        });
      });
    });
  });

  return saml;
}

module.exports = samlRoute;
