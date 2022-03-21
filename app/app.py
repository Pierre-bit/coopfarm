import os  # module contenant des fonctions liées aux info sur l'OS
from app.lib.mongo_connect import mongo
from flask import Flask, jsonify, request
from .services.catalogue_provider import create_document, recover_entries, recover_one_entry, delete_one_entry, \
    update_document
from .lib.security import check_code, htmlspecialchars
from .lib.check_inputs import check_received_data
import re
import bcrypt
import jwt

# initialisation de l'application Flask
app = Flask(__name__)
URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/coopfarm')
app.config["MONGO_URI"] = URI

mongo.init_app(app)

# Récupération des variables d'environnement
PORT = int(os.environ.get('SRV_PORT', 3000))
DEBUG = os.environ.get('SRV_DEBUG', True)
HOST = os.environ.get('SRV_HOST', '0.0.0.0')
SECRET_KEY = os.environ.get('SECRET_KEY', 'thisisasecret')


# routes

# **********************************************
# ******************** POST ********************
# **********************************************

@app.route('/api/catalogue', methods=['POST'])
def new_entry():
    """Fonction servant à controller les données reçues lors d'une requête POST sur l'endpoint '/api/catalogue'.
    Elle appelle le microservice d'authentification en lui fournissant le token afin de le vérifier et de le décoder.
    Elle vérifie les données reçues (intégrité, présence, code malicieux, etc)
    Elle appelle le provider pour créer un nouveau document

    Args:
        - pn (string): alias pour plant_name pour ne pas exposer le nom de l'entrée dans le document
        - bpp (string): alias pour begin_plantper (début de période de plantation) pour ne pas exposer le nom de l'entrée dans le document
        - epp (string): alias pour end_plantper (fin de période dep lantation) pour ne pas exposer le nom de l'entrée dans le document

    Returns:
        - 201 : enregistrement fructueux du document en bdd
        - 400 : requête vide, champs manquant ou mauvais type du champ
        - 403 : token invalide ou code malicieux
        - 409 : données en doublon
        - 500 : erreur innattendue (bdd hors ligne, etc)
    """

    # # Appel au microservice d'authentification pour vérifier le token et le décoder
    # auth_data = call_auth(request)
    # if type(auth_data) == str:
    #     return jsonify({ 'message': auth_data}), 403

    # Vérification du contenu de la requête
    if not request.is_json:
        return jsonify({'message': 'Requête vide'}), 400

    # Récupération du contenu de la requête
    request_data = request.get_json()

    # Vérification des données concernant des caractères dangereux
    try:
        check_code(request_data)
    except:
        return jsonify({'message': 'Présence de caractère dangereux'}), 403

    # Appel à la fonction de vérification des données reçues
    errors = check_received_data(request_data)

    # # Renvoi des erreurs s'il y en a
    if errors is not None:
        if len(errors) != 0:
            return jsonify({'message': errors}), 400

    # Appel du provider pour créer une nouvelle entrée en bdd
    try:
        err = create_document(request_data)
        if err is not None:
            return jsonify({'message': err}), 409
    except:
        return jsonify({'message': 'Erreur inatendue, veuillez contacter l\'administrateur du site'}), 500

    # Renvoi d'un OK
    return '', 201


# *********************************************
# ******************** GET ********************
# *********************************************

@app.route('/api/catalogue/<pn>', methods=['GET'])
def recover_entry(pn: str):
    """Fonction servant appeller le microservice d'authentification en lui fournissant le token afin de le vérifier et de le décoder.
    Elle appelle le provider pour récupérer un document correspondant à l'argument reçu

    Returns:
        - 200 : renvoi le document demandé
        - 404 : aucun document trouvé
        - 500 : erreur innattendue (bdd hors ligne, etc)
    """

    # # Appel au microservice d'authentification pour vérifier le token et le décoder
    # auth_data = call_auth(request)
    # if type(auth_data) == str:
    #     return jsonify({ 'message': auth_data}), 403

    # Vérification des caractères interdits
    if pn != htmlspecialchars(pn):
        return jsonify({'message': 'Présence de caractère dangereux'}), 403

    # Appel au provider pour récupérer le document requis
    try:
        doc = recover_one_entry(pn)
    except Exception as e:
        if e.args[0] == 'KO':
            return jsonify({'message': 'Aucune entrées trouvées'}), 404
        else:
            return jsonify({'message': 'Erreur inatendue, veuillez contacter l\'administrateur du site'}), 500

    return jsonify({'catalogue': doc}), 200


@app.route('/api/catalogue', methods=['GET'])
def get_all_entries():
    """Fonction servant appeller le microservice d'authentification en lui fournissant le token afin de le vérifier et de le décoder.
    Elle appelle le provider pour récupérer tous les documents

    Returns:
        - 200 : renvoi la list des documents demandés
        - 404 : aucun document trouvé
        - 500 : erreur innattendue (bdd hors ligne, etc)
    """

    # # Appel au microservice d'authentification pour vérifier le token et le décoder
    # auth_data = call_auth(request)
    # if type(auth_data) == str:
    #     return jsonify({ 'message': auth_data}), 403

    # Appel au provider pour récupérer tous les documents
    try:
        docs = recover_entries()
    except Exception as e:
        if e.args[0] == 'KO':
            return jsonify({'message': 'Aucune entrées trouvées'}), 404
        else:
            return jsonify({'message': 'Erreur inatendue, veuillez contacter l\'administrateur du site'}), 500

    return jsonify({'catalogue': docs}), 200


# ************************************************
# ******************** DELETE ********************
# ************************************************

@app.route('/api/catalogue/<pn>', methods=['DELETE'])
def delete_entry(pn: str):
    """Fonction servant appeller le microservice d'authentification en lui fournissant le token afin de le vérifier et de le décoder.
    Elle appelle le provider pour supprimé un document précis

    Returns:
        - 204 : document supprimé
        - 404 : aucun document trouvé
        - 500 : erreur innattendue (bdd hors ligne, etc)
    """

    # # Appel au microservice d'authentification pour vérifier le token et le décoder
    # auth_data = call_auth(request)
    # if type(auth_data) == str:
    #     return jsonify({ 'message': auth_data}), 403

    # Vérification des caractères interdits
    if pn != htmlspecialchars(pn):
        return jsonify({'message': 'Présence de caractère dangereux'}), 403

    # Appel au provider pour supprimer le document demandé
    try:
        result = delete_one_entry(pn)
        if result == 0:
            return jsonify({'message': 'Le document n\'a pas été trouvé'}), 404
    except:
        return jsonify({'message': 'Erreur inatendue, veuillez contacter l\'administrateur du site'}), 500

    return jsonify(''), 204


# *********************************************
# ******************** PUT ********************
# *********************************************

@app.route('/api/catalogue/<pn>', methods=['PUT'])
def update_entry(pn: str):
    """Fonction servant à controller les données reçues lors d'une requête PUT sur l'endpoint '/api/catalogue'.
    Elle appelle le microservice d'authentification en lui fournissant le token afin de le vérifier et de le décoder.
    Elle vérifie les données reçues (intégrité, présence, code malicieux, etc)
    Elle appelle le provider pour mettre à jour un nouveau document

    Args:
        - pn (string): alias pour plant_name pour ne pas exposer le nom de l'entrée dans le document
        - bpp (string): alias pour begin_plantper (début de période de plantation) pour ne pas exposer le nom de l'entrée dans le document
        - epp (string): alias pour end_plantper (fin de période dep lantation) pour ne pas exposer le nom de l'entrée dans le document

    Returns:
        - 200 : mise à jour fructueuse du document en bdd
        - 400 : requête vide, champs manquant ou mauvais type du champ
        - 403 : token invalide ou code malicieux
        - 409 : données en doublon
        - 500 : erreur innattendue (bdd hors ligne, etc)
    """

    # # Appel au microservice d'authentification pour vérifier le token et le décoder
    # auth_data = call_auth(request)
    # if type(auth_data) == str:
    #     return jsonify({ 'message': auth_data}), 403

    # Vérification du contenu de la requête
    if not request.is_json:
        return jsonify({'message': 'Requête vide'}), 400

    # Récupération du contenu de la requête
    request_data = request.get_json()

    # Vérification des données concernant des caractères dangereux
    try:
        check_code(request_data)
    except:
        return jsonify({'message': 'Présence de caractère dangereux'}), 403

    # Appel à la fonction de vérification des données reçues
    errors = check_received_data(request_data)

    # # Renvoi des erreurs s'il y en a
    if errors is not None:
        if len(errors) != 0:
            return jsonify({'message': errors}), 400

    # Appel du provider pour créer une nouvelle entrée en bdd
    try:
        err = update_document(pn, request_data)
        if err is not None:
            return jsonify({'message': err}), 409
    except:
        return jsonify({'message': 'Erreur inatendue, veuillez contacter l\'administrateur du site'}), 500

    # Renvoi d'un OK
    return '', 200


# fonction qui retourne un regex pour chaine de caractere
def regex(data):
    """
    Fonction qui cree un regex pour les caractere et chiffres

    Returns:
        _type_: _description_
    """

    # verification que la data accepte soit des caracteres alphabertiques en minuscules ou majuscules ou des chiffres
    data = re.match('^[a-zA-Z]{1,25}$', data)
    return data


# fonction qui vérifie si le login existe déjà en base de données
def check_login_is_exist(data):
    # Vérification de l'unicité du document
    doc = mongo.db.user.find_one({'login': data})
    if doc is not None:
        return 'Login existe déjà en bdd'


@app.route('/login', methods=["POST"])
# Connection utilisateur
def login():
    """
    Fonction qui permet à l'utilsateur de se connecter
    en indiquant son login et mot de passe

    Returns:
        200 : connexion réussi
        401 : le mot de passe indiqué n'est pas accepté
        404: le login n'est pas valable
    """
    data = request.get_json()
    doc = mongo.db.user.find_one({'login': data['login']}, {'_id': 0})
    if doc is None:
        return jsonify({'message': "login not found"}), 404

    if not bcrypt.checkpw(data['password'].encode('utf-8'), doc['password']):
        return jsonify({'message': "password not accept"}), 401

    # creation du token
    token = jwt.encode({"login": doc["login"]}, SECRET_KEY, algorithm="HS256")
    reponse = jsonify({'message': 'login valid'})
    # attache le token dans un cookie
    reponse.set_cookie('coopfarm_token', token)
    return reponse


@app.route('/register', methods=['POST'])
def register():
    """
    Fonction qui enregistre un utilisateur en base de données


    Returns:
      201: utilisateur a bien été enregistrer en base de données
      404: données utilsiateur non valable
      409: login dejà enregistrer
    """

    # donnees recuperer sous format json
    data = request.get_json()

    # verification du login
    match = check_login_is_exist(data['login'])

    # mise en place de regex
    reg_code = re.match('^[0-9]{5}$', data['zip_code'])
    reg_login = regex(data['login'])
    reg_forname = regex(data['forname'])
    reg_lastname = regex(data['lastname'])
    reg_city = regex(data['city'])

    # hashage du mot de passe
    hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    # verification si le login n'est pas deja en base de données
    if match is None:

        # Creation de l'object user
        user = {
            'login': data['login'],
            'password': hash,
            'forname': data['forname'],
            'lastname': data['lastname'],
            'city': data['city'],
            'zip_code': data['zip_code']
        }
        # verification des regex
        if reg_code and reg_login and reg_forname and reg_lastname and reg_city:

            # Insertion en bdd
            mongo.db.user.insert_one(user)
            return jsonify({'result': "created success"}), 201
        else:
            return jsonify({'result': "invalid data"}), 404
    else:
        return jsonify({'result': "duplicate"}), 409


@app.route('/read', methods=['GET'])
# affichage de tous les utilisateurs
def user_read():
    """
    Fonction qui renvoie l'ensemble des utilisateurs

    Returns:
        200: données envoyés
    """
    # affichage des données exceptés le mot de passe et l'id
    users = list(mongo.db.user.find({}, {'password': 0, '_id': 0}))
    return jsonify({'result': users}), 200


@app.route("/replace/<login>", methods=["PATCH"])
# focntion modification de l'utilisateur
def user_update(login):
    """
    Fonction qui modifie les données utilisateurs

    Args:
        login (string): login utilise pour acceder son compte

    Returns:
        200: données utilisateur a bien été mise à jour
        404: données non valide
    """
    data = request.get_json()

    # mise en place de regex
    reg_code = re.match('^[0-9]{5}$', data['zip_code'])
    reg_forname = regex(data['forname'])
    reg_lastname = regex(data['lastname'])
    reg_city = regex(data['city'])

    # verification des regex
    if reg_code and reg_forname and reg_lastname and reg_city:
        # mise en place du filtre
        filter = {'login': login}

        # modification des datas
        try:
            new_forname = {"$set": {'forname': data["forname"]}}
            new_lastname = {"$set": {'lastname': data["lastname"]}}
            new_city = {"$set": {'city': data["city"]}}
            new_zip_code = {"$set": {'zip_code': data["zip_code"]}}

            mongo.db.user.update_one(filter, new_forname)
            mongo.db.user.update_one(filter, new_lastname)
            mongo.db.user.update_one(filter, new_city)
            mongo.db.user.update_one(filter, new_zip_code)
            return jsonify({'result': 'update success'}), 200
        except:
            return "fail"
    else:
        return jsonify({'result': "invalid data"}), 404


@app.route("/delete/<login>", methods=["DELETE"])
# fonction qui permet la suppression d'un utilisateur
def delete_user(login):
    """
    Fonction qui supprime  un utilisateur

    Args:
        login (string): login utilise pour acceder son compte

    Returns:
        200 : utilisateur bien supprimé
    """
    mongo.db.user.delete_one({'login': login})
    return jsonify({'result': 'delete user'}), 200


@app.route('/token', methods=["POST"])
def check_for_token():
    """
    Fonction qui vérifie si le token est present et valide

    Returns:
        200 : token present et valide
        403 : token est invalide ou non présent
    """
    # recuperation de l'entete
    cookie = request.headers['Cookie']
    # recuperation du token dans le cookie
    token = cookie.split('=')[1]

    # verification si presence d'un token
    if not token:
        return jsonify({'message': 'Token missing'}), 403
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return jsonify({'message': 'Invalid token'}), 403

    # verification du login
    doc = mongo.db.user.find_one({'login': data['login']})
    if doc is None:
        return jsonify('acces refused'), 403
    return jsonify("token is valid"), 200


# démarrage du serveur
app.run(host=HOST, port=PORT, debug=DEBUG)
