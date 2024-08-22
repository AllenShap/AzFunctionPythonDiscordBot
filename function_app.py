import azure.functions as func
import aiohttp

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
@app.route(route="", methods=["POST"])
async def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
  body1 = req.get_json()
  await send('Executing command...', body1['id'], body1['token'])
  
  import json
  from nacl.signing import VerifyKey
  from nacl.exceptions import BadSignatureError

  DISCORD_BOT_PUBLIC_KEY = 'DISCORD_BOT_PUBLIC_KEY'
  verify_key = VerifyKey(bytes.fromhex(DISCORD_BOT_PUBLIC_KEY))
  headersAsDict = dict(req.headers)
  signature = headersAsDict['x-signature-ed25519']
  timestamp = headersAsDict['x-signature-timestamp']
  req_body_bytes = req.get_body().decode("utf-8")
  
  try:
      verify_key.verify(f'{timestamp}{req_body_bytes}'.encode(), bytes.fromhex(signature))
  except BadSignatureError:
    return func.HttpResponse(status_code=401, body=json.dumps('invalid request signature'))


  eventType = body1['type']
  if eventType == 1:
    return func.HttpResponse(status_code=200, body=json.dumps({'type': 1}))
  elif eventType == 2:
    return command_execution(body1)
  else:
    return func.HttpResponse(status_code=400, body=json.dumps('unhandled request type'))


async def send(message, id, token):
    url = f"https://discord.com/api/interactions/{id}/{token}/callback"
    callback_data = {'type': 4,'data': {'content': message}}

    async with aiohttp.ClientSession() as session:
      async with session.post(url, json=callback_data) as response:
        await response.text()


def command_execution(body):
  from azure.identity import ManagedIdentityCredential
  from azure.mgmt.compute import ComputeManagementClient
  from azure.mgmt.compute.models import VirtualMachine
  subscription_id = 'AZURE_SUBSCRIPTION_ID'
  resource_group_name = 'RESOURCE_GROUP_NAME_OF_VM'
  vm_name = 'VIRTUAL_MACHINE_NAME'
  credential = ManagedIdentityCredential()
  compute_client = ComputeManagementClient(credential, subscription_id)
  DISCORD_BOT_ID = 'DISCORD_BOT_APPLICATION_ID'
  callback_data = {'type': 1}
  command = body['data']['name']
  
  
  if command == 'palworldstart':
    async_vm_start = compute_client.virtual_machines.begin_start(resource_group_name, vm_name)
    async_vm_start.wait()
    updated_message = ':computer: VM has been started! Please wait 1-2 Minutes to connect. Connection Details: 127.0.0.1:8211 :computer:'
    update(updated_message, body['token'], DISCORD_BOT_ID)
    return func.HttpResponse(status_code=400, headers={'Content-Type': 'application/json'}, body=str(callback_data))
  
  if command == 'palworldstop':
    async_vm_stop = compute_client.virtual_machines.begin_deallocate(resource_group_name, vm_name)
    async_vm_stop.wait()
    updated_message = ':octagonal_sign: Palword VM has been stopped! :octagonal_sign:'
    update(updated_message, body['token'], DISCORD_BOT_ID)
    return func.HttpResponse(status_code=400, headers={'Content-Type': 'application/json'}, body=str(callback_data))
  
  else:
    message = 'This command is not supported'
    send(message, body['id'], body['token'])
    return func.HttpResponse(status_code=400,body='unhandled command')


def update(message, token, app_id):
    import requests
    url = f"https://discord.com/api/webhooks/{app_id}/{token}/messages/@original"
    data = {"content": message}
    response = requests.patch(url, json=data)
