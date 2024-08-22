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
