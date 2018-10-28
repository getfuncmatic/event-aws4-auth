const aws4 = require('aws4')
const eventrequest = require('@funcmatic/event-request')

function dateToAmzDate(t) {
  return `${t.toISOString().replace(/-/g,'').replace(/:/g,'').split('.')[0]}Z`
}

// '20181023T035529Z'
function amzDateToDate(s) {
  var y = s.substring(0, 4)
  var m = s.substring(4, 6)
  var d = s.substring(6, 8)
  var h = s.substring(9, 11)
  var mm = s.substring(11, 13)
  var ss = s.substring(13, 15)
  var isodatestr = `${y}-${m}-${d}T${h}:${mm}:${ss}Z`
  return new Date(isodatestr)
}

function parseAWSV4AuthorizationHeader(authorization) {
  var args = authorization.substring('AWS4-HMAC-SHA256'.length).trim().split(',').map(pair => pair.split('='))
  // args = [ [`Credential', '...'],['SignedHeaders', '...'], ['Signature'='...' ] ]
  var parsed = { }
  for (var pair of args) {
    parsed[pair[0].trim()] = pair[1].trim()
  }
  if (parsed['SignedHeaders']) {
    parsed['SignedHeaders'] = parsed['SignedHeaders'].split(';')  // host;x-amz-date;x-funcmatic-custom-header-1
  }
  return parsed
}

function getAWSV4SignatureFromHeader(authorization) {
  return parseAWSV4AuthorizationHeader(authorization)['Signature']
}

// return {
//   "path": "/dev/files/ENV-UUID/decrypt",
//   "httpMethod": "GET",
//   "headers": {
//       "Accept": "application/json",
//       "X-Forwarded-Proto": "https",
//       "Host": "api.dotenv.io",
//       'X-Funcmatic-Custom-Header-2': 'world',
//       'X-Funcmatic-Custom-Header-1': 'hello',
//       'X-Amz-Date':  util.dateToAmzDate(new Date()),
//       "Authorization": "AWS4-HMAC-SHA256 Credential=6d3592fa-d490-44c0-a6a0-595bd8aa382d/20181027/us-east-1//aws4_request, SignedHeaders=host;x-amz-date;x-funcmatic-custom-header-1;x-funcmatic-custom-header-2, Signature=3d4fef7636e8840a10d98c277277714bac8d205f10b0ac9b2cd8c3ea0f2fced5"
//   },
//   "stageVariables": null,
//   "requestContext": {
//       "requestTimeEpoch": (new Date()).getTime(),
//   }
// }

function createTestEvent(credentials) {
  var event = {
    httpMethod: 'GET',
    path: `/my/path`,
    headers: {
      'X-Funcmatic-Custom-Header-2': 'world',
      'X-Funcmatic-Custom-Header-1': 'hello',
      "X-Forwarded-Proto": "https",
      "Host": "myhost.com",
      "X-Amz-Date":  dateToAmzDate(new Date())
    },
    requestContext: {
      requestTimeEpoch: new Date().getTime()
    }
  }
  var options = eventrequest.toOptions(event)
  var signed = aws4.sign(options, credentials)
  event.headers['Authorization'] = signed.headers['Authorization']
  return event
}

module.exports = {
  dateToAmzDate,
  amzDateToDate,
  parseAWSV4AuthorizationHeader,
  getAWSV4SignatureFromHeader,
  createTestEvent
}