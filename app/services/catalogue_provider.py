from app.lib.mongo_connect import mongo


def create_document(data: dict) -> str:
    """Fonction permettant d'insérer un nouveau document dans la collection

    Args:
        - data (dict): dictionnaire contenant les attributs du document
        - ui (string): id de l'utilisateur

    Returns:
        - str: message d'erreur retourné
        - void: cas où tout s'est bien passé
    """

    # Vérification des mois indiqués
    if data['epp'] == data['bpp']:
        return 'Le mois de fin de période de plantation ne peut pas être le même que celui de début'

    # Création de l'objet à insérer en bdd
    # Pour ne récupérer que les champs qui nous intéressent
    obj = {
        'plant_name': data['pn'],
        'begin_plantper': data['bpp'],
        'end_plantper': data['epp']
    }

    # Vérification de l'unicité du document
    doc = mongo.db.catalogue.find_one({'plant_name': data['pn']})
    if doc is not None:
        return 'Plante déjà en bdd'

    # Insertion en bdd
    mongo.db.catalogue.insert_one(obj)


def recover_entries() -> list:
    """Fonction permettant de retourner tous les documents de la collection
    Retravaille les objets pour ne pas renvoyer d'intitulé de ligne de la bdd

    Returns:
        - result: documents retournés

    Exception:
        - Exception: en cas d'absence de document à retourner
    """

    # Récupère tous les documents
    docs = list(mongo.db.catalogue.find({}, {'_id': 0}))
    if len(docs) == 0:
        raise Exception('KO')
    else:
        # Boucle de conversion des attributs
        result = []
        for doc in docs:
            result.append({
                'pn': doc['plant_name'],
                'bpp': doc['begin_plantper'],
                'epp': doc['end_plantper']
            })
        return result


def recover_one_entry(pn: str) -> object:
    """Fonction permettant de retourner un document précit
    Retravaille les objets pour ne pas renvoyer d'intitulé de ligne de la bdd

    Returns:
        - result: document retourné

    Exception:
        - Exception: en cas d'absence de document à retourner
    """

    # Récupére le document par le plant_name fourni
    doc = mongo.db.catalogue.find_one({'plant_name': pn}, {'_id': 0})
    if doc is None:
        raise Exception('KO')
    else:
        # Boucle de conversion des attributs
        result = {
            'pn': doc['plant_name'],
            'bpp': doc['begin_plantper'],
            'epp': doc['end_plantper']
        }
        return result


def delete_one_entry(pn: str) -> int:
    """Fonction permettant de supprimer un document précit

    Returns:
        - result.deleted_count (int): nombre de documents supprimés (normalement 1)
    """
    # Supprime l'entrée en bdd
    result = mongo.db.catalogue.delete_one({'plant_name': pn})
    return result.deleted_count


def update_document(pn, data) -> str:
    """Fonction permettant de mettre à jour un document dans la collection

    Args:
        - data (dict): dictionnaire contenant les attributs du document
        - ui (string): id de l'utilisateur

    Returns:
        - void: cas où tout s'est bien passé
    """

    # Vérification des mois indiqués
    if data['epp'] == data['bpp']:
        return 'Le mois de fin de période de plantation ne peut pas être le même que celui de début'

    # Création de l'objet à insérer en bdd
    # Pour ne récupérer que les champs qui nous intéressent
    obj = {
        'plant_name': data['pn'],
        'begin_plantper': data['bpp'],
        'end_plantper': data['epp']
    }

    # Remplacement du document
    mongo.db.catalogue.find_one_and_replace({'plant_name': pn}, obj)