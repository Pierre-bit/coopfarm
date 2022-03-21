import re

# Variables
plant = 'Le nom de la plante'
begin_plant = 'Le mois de début de plantation'
end_plant = 'Le mois de fin de plantation'
message1 = ' n\'est pas un string'
message2 = ' ne doit contenir que des lettres et des espaces'
message3 = ' manquant'
message4 = ' n\'est pas un mois valide'


def check_string(string, message1, message2):
    """Fonction vérifiant si le string reçu en est bien un
    Vérifie aussi s'il ne contient bien que des lettres et des espaces
    
    Args:
        - string: le string à vérifier
        
    Returns:
        - message: message d'erreur si la vérification échoue
        - void
    """

    # Vérification du typage
    if type(string) != str:
        return message1

    # Vérification des caractères
    result = re.match('^[a-zA-Z ]*$', string)
    if not result:
        return message2

def check_exist_type(data, message1, message2, message3):

    # Vérification de l'existance de la variable
    try:
        error = check_string(data, message1, message2)
        if error is not None:
            return error
    except:
        return  message3


def check_received_data(data):
    """Fonction vérifiant les données reçues
    
    Args:
        - data (dict): données reçue avec une requête POST/PUT
    
    Returns:
        - errors : liste d'erreurs
        - void
        """
    # Initialisation de la liste contenant les erreurs
    errors = []

    # Initialisation de la liste des mois
    month = ['janvier', 'fevrier', 'mars', 'avril', 'mai', 'juin', 'juillet', 'aout', 'septembre', 'octobre', 'novembre', 'decembre'] 
    
    # Vérification de la présence des champs et de leur type
    try:
        error = check_string(data['pn'], plant + message1, plant + message2)
        if error is not None:
            errors.append(error)
    except KeyError:
        errors.append(plant + message3)          
    try:
        error = check_string(data['bpp'], begin_plant + message1, begin_plant + message2)
        if error is not None:
            errors.append(error)
        else:
            if data['bpp'] not in month:
                errors.append(begin_plant + message4)
    except KeyError:
        errors.append(begin_plant + message3)
    try:
        error = check_string(data['epp'], end_plant + message1, end_plant + message2)
        if error is not None:
            errors.append(error)
        else:
            if data['epp'] not in month:
                errors.append(end_plant + message3)           
    except KeyError:
        errors.append(end_plant + message4)

    # Renvoi des erreurs s'il y en a
    if len(errors) != 0:
        return errors
