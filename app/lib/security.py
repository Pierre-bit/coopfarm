def htmlspecialchars(text) -> str:
    """Equivalent de la fonction htmlspecialchars en php
    
    Args:
        - text : le string à vérifier

    Returns:
        - le même string dont les caractères dangereux ont été remplacés
    """
    return (
        text.replace("&", "&amp;").
        replace('"', "&quot;").
        replace("<", "&lt;").
        replace(">", "&gt;").
        replace("'", "&apos;").
        replace("#", "&danger;")
    )

def check_code(dictionnaire) -> None:
    """Fonction vérifiant un dictionnaire à la recherche de caractère dangereux.
    
    Args:
        - dictionnaire : le dictionnaire à vérifier
        
    Exception :
        - soulève une exception si un caractère interdit à été trouvé
    """

    # Boucle de vérification
    for i in dictionnaire:
        if type(dictionnaire[i]) == str: # Ne prend en compte que les string pour la vérification
            if dictionnaire[i] != htmlspecialchars(dictionnaire[i]):
                raise Exception("KO") 
    
