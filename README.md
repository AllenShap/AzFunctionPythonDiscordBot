# Discord

Discord Bot using Azure Functions.

This repo serves as an example of how I implemented a Discord bot using the Python v2 model on Azure Functions. This method is implemented via the Interactions Endpoint Url on the Discord bot side.
![image](https://github.com/user-attachments/assets/28c34770-3c29-489b-885e-bb68ad74fee4)



Initially, I was really hoping to be able to pull this off using the most basic Azure Functions hosting plan which is the Consumption based pay-as-you-go plan, however, after much tinkering I found the cold start time ( 0 - 30 seconds ) simply too great and too variable in it’s time to start in order to use it while maintaining a seamless user-facing experience. If you’re looking for something as true to the meaning of “serverless” as possible, then Cloudflare workers are infinitely superior for implementing this over Azure Functions as for a Discord bot use case they are basically free and have a 0ms cold start time (https://workers.cloudflare.com/) 



That being said, For all intents and purposes, using the Azure Functions Consumption based pay-as-you-go plan does actually perform and function as needed and every slash command that is used is indeed executed to completion it’s just that there’s really no indicator of success to the end user of the command. Discord requires an HTTP response within 3 seconds of their servers making an HTTP POST request to your endpoint and if that 3 second response time is not met then the user will simply be faced with an error message from the bot  “The application did not respond”

![image](https://github.com/user-attachments/assets/331d5574-733a-4748-b7a1-fdf64d0a7e2d)




With the Discord 3 second response time limit along with the Azure Functions cold start time in mind, It’s essential to have as least imported libraries as possible as any imports before sending a response simply contribute to using up the 3000ms you get for a response. This explains why I lazy imported my libraries as the first and foremost thing someone should care about is getting a response to discord as fast as possible in order to not get the front facing user error “The application did not respond”.


Since I am not using the commonly mentioned discord.py library, the registration of slash commands in a discord server and the execution of them are decoupled, to register the slash commands your discord bot will have the option to execute, run some variation of the following script. In my case I wanted my initial Discord bot to have 2 commands which start and stop a Virtual Machine in Azure which hosts a Palworld game server to play with my friends. Take note of the name of the commands you decide to implement as these names will be used in the backend python code.

```python
import requests

APP_ID = "DISCORD_BOT_APPLICATION_ID"
SERVER_ID = "DISCORD_SERVER_ID_OF_WHERE_THIS_BOT_IS_LOCATED_IN"
BOT_TOKEN = "DISCORD_BOT_CLIENT_SECRET"


url = f'https://discord.com/api/v10/applications/{APP_ID}/guilds/{SERVER_ID}/commands'

json = [
  {
    'name': 'palworldstop',
    'description': 'Stops the active PalworldVM.',
    'options': []
  },
  {
    'name': 'palworldstart',
    'description': 'Starts a PalworldVM which you can connect to after about 1-2minutes. ',
    'options': []
  }
]
response = requests.put(url, headers={
  'Authorization': f'Bot {BOT_TOKEN}'
}, json=json)

print(response.json())
```
Running the above script successfully will result the discord server your bot is in to have the following:
![image](https://github.com/user-attachments/assets/9ec3f9d1-7296-4234-bb63-c51254d7cb47)


Since there's not many examples online of an Azure Functions implementation, naturally, I looked for AWS Lambda implementations which should be somewhat similar to an Azure Functions implementation. The one thing I think is worth noting is I noticed that most AWS Lambda implementations I saw were different on how they parse the JSON request body.

The following is an AWS Lamda API Gateway code snippet.
```python
def lambda_handler(event, context):
  try:
    body = json.loads(event['body'])
        
    signature = event['headers']['x-signature-ed25519']
    timestamp = event['headers']['x-signature-timestamp']
```
The following is an Azure Functions HTTPTrigger code snippet.
```python
def http_trigger(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
  jsonBody = req.get_json()

  headersAsDict = dict(req.headers)
  signature = headersAsDict["x-signature-ed25519"]
  timestamp = headersAsDict["x-signature-timestamp"]
```
As you might see, the AWS Lambda code is accessing the headers of the JSON body being sent by Discord directly in the "event' object. Whereas the Azure snippet is converting the "req" object into a dictionary before it is accessing the [required](https://discord.com/developers/docs/interactions/overview#setting-up-an-endpoint) ```"x-signature-ed25519"``` and ```"x-signature-timestamp"``` headers. This is because actually (and to my surprise), Azure Functions completely strips the headers off any incoming HTTP Request, one might think that ```jsonBody = req.get_json()``` or ```jsonBody = req.get_body()``` would allow you to simply access the headers with some variation of ```jsonBody['headers']['x-signature-ed25519']``` but that's not the case and the "req" object has to be turned into a dictionary ```dict(req.headers)```. It doesn't help that there is no [documentation](https://learn.microsoft.com/en-us/python/api/azure-functions/azure.functions.httprequest?view=azure-python#azure-functions-httprequest-get-body) on these methods.

The following is pretty much the bare minimum needed to succeed in the Discord API endpoint validation with Azure Functions.
```python
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
```
The following is an example of what a more developed Discord bot could look like. This is built off the code block shown above. The first send() function is called as soon as possible to try and get a response back to Discord within 3 seconds. After that, lazy importing is implemented since there is no longer a 3 second time constraint. The new time constraint turns into 15 minutes to update the initial message we sent in the first 3 seconds to one with the content we want the Discord bot to display.
```python
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
------------------
requirements.txt:

azure-functions
pynacl
requests
azure-identity
azure-mgmt-compute
aiohttp 
```
