const signature = require('../lib/auth')
const aws4 = require('aws4')

const credentials = {
  accessKeyId: process.env.DOTENVIO_ACCESS_KEY_ID,
  secretAccessKey: process.env.DOTENVIO_SECRET_ACCESS_KEY
}

describe('Verify Signature', async () => {
  var testevent = null
  beforeEach(async () => {
    testevent = createTestEvent()
  })
  it ('should verify a signature', async () => {
    var s = signature.auth(testevent, credentials)
    expect(s).toBeTruthy()
  })
  it ('should deny for bad credentials', async () => {
    var error = null
    try {
      var s = signature.auth(testevent, {
        accessKeyId: process.env.DOTENVIO_ACCESS_KEY_ID,
        secretAccessKey: "BAD-SECRET-KEY"
      })
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("SignatureDoesNotMatch")
  })
  it ('should deny for changed header value', async () => {
    testevent.headers['X-Funcmatic-Custom-Header-2'] = 'changedvalue'
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("SignatureDoesNotMatch")
  })
  it ('should deny for a missing header', async () => {
    delete testevent.headers['X-Funcmatic-Custom-Header-2']
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("SignatureDoesNotMatch")
  })
  it ('should deny for different url path', async () => {
    testevent.path = "/my/different/path"
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("SignatureDoesNotMatch")
  })
  it ('should deny for different host', async () => {
    testevent.headers['Host'] = "my.different.host.com"
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("SignatureDoesNotMatch")
  })
  it ('should deny for different query params', async () => {
    testevent.queryStringParameters = { "hello": "world" }
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("SignatureDoesNotMatch")
  })
  it ('should deny if not AWS v4 signed', async () => {
    testevent.headers['Authorization'] = "Bearer my-token"
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("InvalidSignature")
  })
  it ('should deny request and server time off', async () => {
    testevent.requestContext.requestTimeEpoch = new Date().getTime()
    var error = null
    try {
      signature.auth(testevent, credentials)
    } catch (err) {
      error = err
    }
    expect(error).toBeTruthy()
    expect(error.message).toBe("RequestTimeTooSkewed")
  })
})

function createTestEvent() {
  return {
    "resource": "/files/{proxy+}",
    "path": "/dev/files/ENV-UUID/decrypt",
    "httpMethod": "GET",
    "headers": {
        "Accept": "application/json",
        "X-Forwarded-Proto": "https",
        "Host": "api.dotenv.io",
        'X-Funcmatic-Custom-Header-2': 'world',
        'X-Funcmatic-Custom-Header-1': 'hello',
        'X-Amz-Date':  '20181027T063853Z',
        "Authorization": "AWS4-HMAC-SHA256 Credential=6d3592fa-d490-44c0-a6a0-595bd8aa382d/20181027/us-east-1//aws4_request, SignedHeaders=host;x-amz-date;x-funcmatic-custom-header-1;x-funcmatic-custom-header-2, Signature=3d4fef7636e8840a10d98c277277714bac8d205f10b0ac9b2cd8c3ea0f2fced5"
    },
    "stageVariables": null,
    "requestContext": {
        "requestTimeEpoch": 1540622333000,
    }
  }
}