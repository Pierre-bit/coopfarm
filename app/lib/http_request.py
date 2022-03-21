import os
import requests, json


def call_auth(request):
    # Récupération de l'url de l'endpoint du microservice d'authentification pour vérifier/décoder le token
    MSRV_URL = os.environ.get('MSRV_AUTH_URI')
    # Récupération du cookie
    cookie = request.cookies['coopfarm']

    # Requêtage au microservice pour vérification du token et récupération du contenu
    url = MSRV_URL
    headers = {'Content-type': 'application/json; charset=UTF-8'}
    response = requests.post(url, headers, cookies=cookie)
    if response.status_code != 200:
        return 'Token invalide'
    ui, user_status = json.loads(response.content)['ui'], json.loads(response.content)['user_status']

    # Retourne les informations récupérées
    return ui, user_status

