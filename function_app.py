import azure.functions as func
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import json


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
@app.route(route="", methods=["POST"])
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
  body1 = req.get_json()

  DISCORD_BOT_PUBLIC_KEY = 'YOUR_DISCORD_BOT_PUBLIC_KEY_HERE'
  verify_key = VerifyKey(bytes.fromhex(DISCORD_BOT_PUBLIC_KEY))
  headersAsDict = dict(req.headers)
  signature = headersAsDict["x-signature-ed25519"]
  timestamp = headersAsDict["x-signature-timestamp"]
  req_body_bytes = req.get_body().decode("utf-8")

  try:
      verify_key.verify(f'{timestamp}{req_body_bytes}'.encode(), bytes.fromhex(signature))
  except BadSignatureError:
    return func.HttpResponse(status_code=401, body=json.dumps('invalid request signature'))
  
  eventType = body1['type']
  if eventType == 1:
    return func.HttpResponse(status_code=200, body=json.dumps({'type': 1}))
  elif eventType == 2:
    return func.HttpResponse(status_code=200, body=json.dumps({'type': 1}))
  else:
    return func.HttpResponse(status_code=400, body=json.dumps('unhandled request type'))
------------------
requirements.txt:

azure-functions
pynacl
