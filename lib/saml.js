var express = require('express');
var bodyParser = require('body-parser');
var cors = require('cors');
var xml2js = require('xml2js');
var fh = require('fh-mbaas-api');
var parseString = xml2js.parseString;
var stripPrefix = xml2js.processors.stripPrefix;
var normalize = xml2js.processors.normalize;
var path = require('path');
var request = require('request');

function samlRoute() {
  var saml = new express.Router();
  saml.use(cors());
  saml.use(bodyParser());

  saml.all('/login/ok', function(){
    var newUrl = process.env.SAML_SERVICE || 'https://bombardier-e7rjjcdl3f4qadrerth6qa7g-dev.mbaas1.us.feedhenry.com';
    newUrl = path.join(newUrl, '/login/ok');
    console.log('getting ' + newUrl);
    return request.get({url : newUrl }).pipe(res);
  });

  saml.all('/saml/consume', function(req, res){
    // Intra-service call to our SAML service to SSO the ID
    var newUrl = process.env.SAML_SERVICE || 'https://bombardier-e7rjjcdl3f4qadrerth6qa7g-dev.mbaas1.us.feedhenry.com';
    newUrl = path.join(newUrl, '/login/callback');
    console.log('got body');
    console.log(req.body);
    console.log('fwderz to');
    console.log(newUrl);
    return request.post({url : newUrl, json : req.body }).pipe(res);
    // return fh.service({
    //   "guid": process.env.SAML_SERVICE || "e7rjjcdl3f4qadrerth6qa7g",
    //   "path": "/login/callback",
    //   "method": "POST",
    //   "params": req.body
    // }, function(err, body, serviceResponse) {
    //   if (err) {
    //     // An error occurred 
    //     return res.status(500).json({ responseFromSiteminder : res.body, errorFromService : err });
    //   }
    //   console.log('response from service:');
    //   console.log(serviceResponse.body);
    //   return res.status(200).json({ responseFromSiteminder : req.body, responseFromService : body });
    // });

    
    
    return res.json({ok : true});
  });
  
  saml.post('/saml/login', function(req, res){
    function gotResponse(body){
      var samlBody = /value\s?=\s?"([a-zA-Z0-9+=\/\s]+)">/g,
      samlAssertion = samlBody.exec(body);
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
    }
    
    
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
      jar : true,
      headers : {
        'Cookie' : 'SMCHALLENGE=YES'
      }
    }, function(err, response, body){
      if (response && response.statusCode === 200){
        return gotResponse(response.body);
      }
      
      if (err || !response.headers || !response.headers.location){
        return res.status(500).json(err || 'No redirect found');
      }
      // Step 2 - follow the redirect, picking up cookies along the way as part of the 
      // Federation - Affwebservices basic auth challenge
      var newUrl = response.headers.location;
      request.get({
        url : newUrl,
        jar : true
      }, function(err){
        if (err){
          return res.status(500).json(err);
        }
        // Now that we've picked up all the cookies we need, this is the "money shot". 
        // A reply from this should give us our SAML response. 
        request.get({
          url : newUrl,
          jar : true,
          auth : auth
        }, function(err, response, body){
          if (err){
            return res.status(500).json(err);
          }
          if (response.statusCode !== 200){
            return res.status(response.statusCode).end(body);
          }
          return gotResponse(response.body);
        });
      });
    });
  });

  return saml;
}

module.exports = samlRoute;
