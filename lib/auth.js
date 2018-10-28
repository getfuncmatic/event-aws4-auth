const url = require('url')
const aws4 = require('aws4')
const eventrequest = require('@funcmatic/event-request')
const util = require('./util')

const DEFAULT_SKEW_TOLERANCE = 5 * 1000 // 5 seconds

// Verify if the AWS V4 signature given in the 'Authorization' header 
// matches the event. 'event' is assumed to be an AWS Lambda Proxy Event
function auth(event, credentials, options) {
  var options = options || { }
  var skew = options.skew || DEFAULT_SKEW_TOLERANCE
  if (!isAWS4Signed(event)) {
    throw new Error("InvalidSignature")
  }
  if (isRequestTimeTooSkewed(event, skew)) {
    throw new Error("RequestTimeTooSkewed")
  }
  var clientSignature = util.getAWSV4SignatureFromHeader(event.headers['Authorization']) 
  if (options.verbose) console.log("CLIENT", event, clientSignature)
  var serverEvent = sign(event, credentials)
  var serverSignature = serverEvent.signature
  if (options.verbose) console.log("SERVER", serverSignature, serverEvent)
  if (clientSignature != serverSignature) {
    throw new Error("SignatureDoesNotMatch")
  }
  return clientSignature
}

function sign(event, credentials) {
  // construct vanilla http(s) request options from the event
  var opts = eventrequest.toOptions(event)
  // replace the full client headers with only the ones that the client signed
  opts.headers = extractSignedHeaders(event)
  // sign the request using the aw4 library
  var signed = aws4.sign(opts, credentials)
  var signature = util.getAWSV4SignatureFromHeader(signed.headers['Authorization'])
  return {
    signature,
    signed,
    options: opts
  }
}

function isAWS4Signed(event) {
  var authorization = event.headers && event.headers['Authorization']
  return authorization && authorization.startsWith('AWS4-HMAC-SHA256')
}

function isRequestTimeTooSkewed(event, skew) {
  var serverRequestTime = new Date(event.requestContext.requestTimeEpoch) // 1540265988530 
  var clientRequestDate = util.amzDateToDate(event.headers['X-Amz-Date'] || event.headers['x-amz-date']) 
  return (Math.abs(clientRequestDate - serverRequestTime) > skew) 
}

function extractSignedHeaders(event) {
  var headers = { }
  var authorization = event.headers && event.headers['Authorization']
  var signedHeaders = util.parseAWSV4AuthorizationHeader(authorization)['SignedHeaders'] 
  for (name in event.headers) {
    if (signedHeaders.includes(name.toLowerCase())) {
      headers[name] = event.headers[name]
    }
  }
  return headers
}

module.exports = {
  auth,
  sign
}
