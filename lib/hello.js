var express = require('express');
var bodyParser = require('body-parser');
var cors = require('cors');

function helloRoute() {
  var hello = new express.Router();
  hello.use(cors());
  hello.use(bodyParser());


  // GET REST endpoint - query params may or may not be populated
  hello.all('/saml/consume', function(req, res){
    console.log(req.body);
    return res.json({ok : true});
  });

  return hello;
}

module.exports = helloRoute;
