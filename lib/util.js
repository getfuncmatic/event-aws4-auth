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


module.exports = {
  dateToAmzDate,
  amzDateToDate,
  parseAWSV4AuthorizationHeader,
  getAWSV4SignatureFromHeader
}