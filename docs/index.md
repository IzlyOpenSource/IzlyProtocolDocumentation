Le protocole Izly
=================

Ce document décrit le protocole permettant la communication entre l'application smartphone Izly (client), et les serveurs Izly. Ces informations ont été obtenues via le sniffing du protocole sous Android, et sont donc potentiellement incompletes, inexactes, etc. 

Toutefois, elles suffisent normalement à effectuer les opérations courantes (s'identifier sur le service, rechargher son compte, etc.)

Ce document (incluant le code d'exemple ̀`freezly.py`) est diffusé sous la licence "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE" (aka WTFPL, disponible sur <http://sam.zoy.org/wtfpl/COPYING>), dans l'espoir de contribuer au développement d'un client libre, sans pubs ni tracking...

Vue d'ensemble
--------------

La plupart des actions réalisables depuis l'appli smartphone sont effectuées grâce à l'invocation d'une méthode distante sur le serveur SOAP. Chaque requete SOAP est caracterisée par un nom de methode, et une liste d'arguments.

La seule exception est le paiement à une borne de paiement (Resto-U / RU), qui se fait par le scan d'un QRCode. Ce QRCode est généré par l'application sans avoir besoin de communiquer avec le réseau.

La section suivante donne les grandes lignes du fonctionnement de l'authentification. Les détails sont présentés dans les sections suivantes.

### I. Authentification

D'abord la sous-section suivante donnera une liste et description des valeurs impliquées dans les processus d'authentification. Le fonctionnement exact de l'authentification et l'utilisation de ces valeurs sera expliqué ensuite.

#### I.a Elements utilisés dans l'authentification

Ces differents elements interviennent dans l'authentification :

- user : le numero de telephone de l'utilisateur au format international (c a d 336NNNNNNNN et non 06NNNNNNNN)
- password : le code secret à 6 chiffres de l'utilisateur
- code d'activation : un code recu par SMS lors de la premiere authentification
- sessionid et token : elements representant la session active. Ils sont envoyés par le serveur après une authentification réussie, puis ensuite le client doit les envoyer au serveur a chaque requête.
- compteur : entier sur 64bits (re-)initialise a 0 lors de l'authentification, et incrementé lors de certaines opérations (précisées plus bas)

Les requetes sur le service SOAP, ainsi que la génération des QRCodes, vont utiliser certains des élements d'authentification.

#### I.b Fonctionnement général de l'authentification

Cette section explique le principe general de l'authentification, et uniquement les arguments principaux sont donnés. Le format exact des requetes sera donné dans la section III

L'authentification suit un processus différent, selon que c'est la première fois qu'on s'authentifie, ou bien qu'on rafraichit une session expirée.

Etapes de la premiere authentification:

Etape 0) Le compteur est initialise a 0

Etape 1) Invocation SOAP du Client vers le Serveur:
 - Nom de methode: Login
 - Arguments principaux: 
   - user
   - password

Etape 2) L'utilisateur recoit un SMS contenant le code d'activation

Le SMS contient une URL de type : `https://mon-espace.izly.fr/tools/Activation/336NNNNNNNN/XXXXXXXX`

Le code d'activation est la derniere partie de l'URL (dans ce cas: XXXXXXXX)

Etape 3) Invocation SOAP du Serveur vers le Client:
- Nom de methode: Login
- Arguments principaux:
  - user
  - signature (valeur hachée) dépendante du code d'authentification et du compteur

Etape 4) Réponse (du Serveur vers le Client) à l'invocation SOAP, contenant:
- sessionId
- token

Etape 5) Incrémentation du compteur


Si la session expire, alors on peut utiliser une version simplifiee de l'authentification pour la "rafraichir", sans avoir besoin de renvoyer un SMS.

Etapes de l'authentification simplifiee:

Etape 0) la valeur du compteur n'est pas remise a 0

Etape 1) Invocation SOAP du Serveur vers le Client:
- Nom de methode: Login
- Arguments principaux:
  - user
  - password
  - signature (valeur hachée) dépendante du code d'authentification, du password, et du compteur

Etape 2) Réponse (du Serveur vers le Client) à l'invocation SOAP, contenant:
- sessionId
- token

Etape 3) Incrémentation du compteur


Ensuite, toutes les autres opérations nécessitent une requete SOAP, qui sera authentifiée par l'envoi systematique du token et du sessionId à chaque requete. Les seules exceptions sont certaines operations "sensibles" qui auront besoin d'element d'authentification specifiques, en plus du token et du sessionId (cela sera précisé dans la section III)

### II. Fonctionnement des requetes SOAP

#### II.a Format géneral des requêtes

Les requêtes sont des invocations de méthodes distantes réalisées avec SOAP à l'adresse https://soap.izly.fr/Service.asmx?WSDL

Toutes les méthodes prennent des arguments de type String, et renvoient une valeur de type String.

Il y a des arguments communs à toutes les requetes (tous de type "string"), ces arguments doivent être envoyés à chaque requête (même si ce n'est pas explicité lors de la description de la requête dans le présent document):
- Nom: "format", Valeur: `"T"`
- Nom: "channel", Valeur: `"AIZ"`
- Nom: "model", Valeur: `"A"`

En d'autre termes, chaque requête correspond à une invocation distante d'une méthode de signature suivante : 

String NomRequete(String format, String channel, String model, ...)

La String renvoyée par la requête est un document au format XML, encodé en "html entities" (caractères < et > remplacés par &lt; et &gt; respectivement).

#### II.b Arguments véhiculant des données d'authentification

En plus de ces arguments, toutes les requetes autres que celles d'authentification (c-a-d invoquant la méthode Login), comportent aussi ces arguments supplémentaires (ces arguments supplémentaires doivent être envoyés également dans ce cas de figure, même si ce n'est pas explicité lors de la description de la requête):
- Nom: "version", Valeur: `"6.0"`
- Nom: "sessionId", Valeur: \<le sessionId tel qu'il a été renvoyé par le serveur lors de l'authentification\>
- Nom: "userId", Valeur: \<numero de telephone\>

De plus, au niveau HTTP, les requêtes autres que celles d'authentification comportent le header suivant:
Authorization: Bearer \<le token tel qu'il a été renvoyé par le serveur lors de l'authentification\>

### III Liste des requêtes avec descriptions

Les sections suivantes décrivent quelques requêtes utiles pour réaliser les opérations basiques. Ce n'est pas exhaustif, mais les autres requêtes sont probablement de structure similaires.

Pour chacune des requêtes décrite, les informations suivantes sont données:
- Nom de la méthode invoquée via SOAP
- Liste et signification des arguments de la mehode (cette liste n'inclus pas les arguments communs, qui doivent être envoyés de toute facon à chaque requête... et il faut egalement penser au header "Authorization:" au niveau HTTP lorsque c'est nécessaire).

Pour la réponse (document XML sous forme de String) à la requete, une description exhaustive n'est pas donneé. A la place, une liste d'informations "intéressantes" est donnée, ainsi que le "chemin" où elles se trouvent dans le document XML.

Par exemple, si une information est dans un element XML Elem2, lui-meme contenu dans Elem1, le chemin sera donne sous la forme suivante: /Elem1/Elem2

La plupart des requêtes pouvant échouer renvoient un noeud "Error" sous le chemin XML /E/Error en cas d'erreur (et un message d'erreur sous /E/Msg). Ceci ne sera pas précisé à chaque description de requête.

#### III.a Authentification en deux étapes (etape 1)

Méthode SOAP invoquée: Login

Arguments (tous de type "string"):
- Nom: "rooted", Valeur: `"0"` (hypothèse: cela indique si le téléphone est rooté? Je n'ai pas investigué.)
- Nom: "smoneyClientType", Valeur: `"PART"`
- Nom: "user", Valeur: \<numerotelephone\>
- Nom: "password", Valeur: \<password\>

Exemple de corps complet de la requête (ce corps complet est donné à titre d'exemple uniquement pour cette requete, pour les suivantes seule la liste des arguments sera donnée) : 
```xml
<?xml version="1.0" encoding="utf-8"?>
<v:Envelope xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:d="http://www.w3.org/2001/XMLSchema" xmlns:c="http://schemas.xmlsoap.org/soap/encoding/" xmlns:v="http://schemas.xmlsoap.org/soap/envelope/">
<v:Header />
  <v:Body>
      <Logon xmlns="Service" id="o0" c:root="1">
      <version i:type="d:string">6.0</version>
      <channel i:type="d:string">AIZ</channel>
      <format i:type="d:string">T</format>
      <model i:type="d:string">A</model>
      <language i:type="d:string">fr</language>
      <user i:type="d:string">33611223344</user>
      <password i:type="d:string">123456</password>
      <smoneyClientType i:type="d:string">PART</smoneyClientType>
      <rooted i:type="d:string">0</rooted>
    </Logon>
  </v:Body>
</v:Envelope>
```

En cas de succès, le numéro de téléphone de l'utilisateur est renvoyé.

Exemple de corps complet de réponse à la requête en cas de succès (ce corps complet est donné à titre d'exemple uniquement ici, dans les sections suivantes il sera donné uniquement le "chemin" pour accéder aux informations intéressantes dans la réponse XML).

```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Body>
    <LogonResponse xmlns="Service">
      <LogonResult>
        &lt;UserData&gt;&lt;UID&gt;33611223344&lt;/UID&gt;&lt;SALT&gt;XXXXXXXXXXXXXXXX&lt;/SALT&gt;&lt;/UserData&gt;
      </LogonResult>
    </LogonResponse>
  </soap:Body>
</soap:Envelope>
```

Une fois décodé, la chaîne renvoyé par la méthode est:
```xml
<UserData>
  <UID>33611223344</UID>
  <SALT>XXXXXXXXXXXXXXXX</SALT>
</UserData>
```

Informations intéressantes dans la réponse XML:
- En cas de succès, numéro de téléphone sous le chemin : /UserData/UID

#### III.b Authentification en deux étapes (etape 2)

Méthode SOAP invoquée: Login

Arguments (tous de type "string"):
- Nom: "rooted", Valeur: `"0"̀`
- Nom: "smoneyClientType", Valeur: `"PART"`
- Nom: "user", Valeur: \<numerotelephone>\
- Nom: "password", Valeur: "" (l'argument existe mais contient la chaine vide, sa valeur semble etre ignorée)
- Nom: "passOTP", Valeur: \<OTP\> (calcul décrit ci dessous)

La valeur de l'OTP est calculée comme suit à partir du code d'activation et du compteur:

Soit A = la chaine de caractères ASCII contenant le code d'activation reçu par SMS.
Soit B = Base64Decode(A). Par exemple si A est la chaine ASCII `"MTIzNDU2"`, alors B est la chaine ASCII `"123456"`
Soit C = la séquence de 8 octets représentant la valeur du Compteur sur 64 bits, en big-endian.
Soit D = La signature HMAC-SHA1 du message C, signé avec la clé B.

La valeur de l'OTP est la signature D encodé en Base64, dans laquelle:
 - Le caractère `/` est remplacé par `_`
 - Le caractère `+` est remplacé par `-`

Après cette requête, le Compteur est incrémenté.

En cas de succès, la réponse contient plusieurs infos, dont les plus utiles sont:
- Le SessionID, contenu dans le noeud XML sous le chemin: /Logon/SID
- Le token, contenu dans le noeud XML sous le chemin: /Logon/OAUTH/ACCESS\_TOKEN

#### III.c Authentification simplifiée (rafraichissement de session expirée)

Méthode SOAP invoquée: Login

Arguments (tous de type "string"):
- Nom: "rooted", Valeur: `"0"`
- Nom: "smoneyClientType", Valeur: `"PART"`
- Nom: "user", Valeur: \<numerotelephone\>
- Nom: "password", Valeur: \<password\>
- Nom: "passOTP", Valeur: \<password\> . \<OTP\> (l'opération . représente la concaténation de chaîne)

La valeur de l'OTP est calculée comme dans l'étape 2 de l'authentification à deux étapes (la seule différence est donc que l'argument passOTP est préfixé par le password de l'utilisateur;

Apres cette requête, le Compteur est incrémenté.

En cas de succès, la réponse contient plusieurs infos, dont les plus utiles sont:
- Le SessionID, contenu dans le noeud XML sous le chemin: /Logon/SID
- Le token, contenu dans le noeud XML sous le chemin: /Logon/OAUTH/ACCESS\_TOKEN

#### III.d Historique des operations

Nom de la méthode invoquée: GetStatement

Arguments (tous de type "string"):
- Nom: "filter", Valeur: `"-1"`
- Nom: "nbItems", Valeur: `"0"`
- Nom: "firstId", Valeur: `"-1"`
Hypothèse (non testée): on peut filtrer les types d'opération à afficher, leur nombre, et la première opération à afficher en faisant varier les valeurs respectivement de "filter", "nbItems", et "firstId". 

La méthode renvoie une liste des opérations (rechargement, paiement au RU, etc) sous forme XML. Il y a un ensemble de noeuds nommés "P" sous le chemin /RPL/TOTAL/P, chaque noeud "P" décrit une opération, et contient des sous-noeuds relatifs à cette opération (date, montant, etc.)

#### III.e Lister les cartes bancaires enregistrees

Nom de la méthode invoquée: MoneyInCbCbList

Arguments: rien (hormis, bien sur, les arguments communs)

Informations importantes en retour:
- L'identifiant de la carte bancaire dans le noeud XML sous le chemin: /RCBL/CBL/CB/ID
Hypothèse (non testée car je n'ai pas 2 cartes bancaires): s'il y a plusieurs cartes bancaires sur le compte, alors il y aura plusieurs noeuds XML nommés "CB", chacun contenant un sous-noeud ID à valeur différente.

#### III.f Recharger le compte a partir de la carte

Nom de la méthode invoquée: MoneyInCb

Arguments:
- Nom: "cardId", Valeur: \<identifiant de la carte (tel que donné par la méthode MoneyInCbCbList)\>
- Nom: "amount", Valeur: \<montant en EUR a crediter sur le compte\>

En cas de succès, le rechargement est préparé, il faut maintenant le confirmer avec la méthode MoneyInCbConfirm (ci-dessous).

#### III.g Confirmation du rechargement

Nom de la méthode invoquée: MoneyInCbConfirm

Arguments:
- Nom: "cardId", Valeur: \<identifiant de la carte (tel que donné par la méthode MoneyInCbCbList)\>
- Nom: "amount", Valeur: \<montant en EUR a crediter sur le compte\>
- Nom: "passOTP", Valeur: \<password\> . \<OTP\> (l'opération . représente la concaténation de chaîne)
- Nom: "print", Valeur: voir la description ci-dessous.

La valeur de l'OTP est calculée de manière identique à ce qui est fait dans les requêtes d'authentification. La valeur de l'argument "passOTP" est l'OTP préfixé par le mot de passe de l'utilisateur.

La valeur de l'argument "print" est calculée comme suit:

Soit A = la chaine ASCII \<numero de telephone\> . "," . \<session id\> . "," . \<id carte\> . "," . \<montant\> . "," . \<OTP\>
(dans cette chaine, l'OTP est la valeur directe de l'OTP, non-préfixée par le mot de passe)
Soit B = La signature HMAC-SHA1 de la chaine A, avec l'OTP utilisé comme clé.

La valeur de l'argument "print" est la signature B encodé en Base64, dans laquelle:
 - Le caractère `/` est remplacé par `_`
 - Le caractère `+` est remplacé par `-`

La valeur du Compteur est incrémentée après cette requête.

L'outil
-------

AVERTISSEMENT : Cet outil est un simple exemple de demonstration pour illustrer la documentation du protocole. Il n'est pas prevu pour etre utilise en situation reelle. Il a ete realise a partir d'informations obtenues par reverse-engineering, donc potentiellement incompletes ou inexactes. Il a ete tres peu teste, il contient probablement des bugs, qui peuvent entrainer des consequences facheuses pour votre ordinateur, votre compte Izly, vos informations bancaires, etc...

L'outil necessite Python 3, et un certain nombre de modules (installables avec apt-get ou pip), vous pouvez regarder les imports pour savoir quels modules sont necessaires.

Pour commencer a utiliser l'outil, vous devez d'abord vous authentifier. Ensuite, l'etat de votre session sera enregistree dans le fichier "authstate.dat" (dans le dossier courant). Vous pouvez effacer ce fichier pour "oublier" l'état de la session (vous devrez alors vous re-authentifier).

Vous pouvez editer freezly.py pour modifier le nom/chemin du fichier "authstate.dat", et vous pouvez aussi modifier les variables DEBUG et TRACE pour obtenir, respectivement, des informations de debug, et une trace complete des requetes et reponses SOAP.

Pour obtenir la liste des commandes disponibles, lancer ./freezly.py (sans arguments).

Scenario typique d'utilisation: 

`$ ./freezly.py login <phone> <password>̀`

L'utilisateur recoit une URL d'activation par SMS, de type:

`https://mon-espace.izly.fr/tools/Activation/336NNNNNNNN/XXXXXXXX`

Le code d'activation est la derniere partie de l'URL (dans ce cas: XXXXXXXX)

`$ ./freezly.py activation <codeactivation>`

L'utilisateur suis maintenant authentifié

`$ ./freezly.py historique`

La commande affiche la liste des paiements effectués

`$ ./freezly.py listecb`

La commande affiche la liste des cartes bancaires avec leur identifiant (hexadecimal, 32 chiffres)

`$ ./freezly.py recharger <idcarte> <montant>`

La commande prepare le rechargement du compte (paiement avec la carte indiquee).
Attention: idcarte est l'identifiant de la carte bancaire (tel que renvoye par listecb) et pas le numero de la carte.

Pour valider le rechargement il faut confirmer avec la commande suivante:
`$ ./freezly.py confirmer <idcarte> <montant> <password>`

Le rechargement est maintenant effectue.

Si jamais la session expire, on peut se re-authentifier de maniere plus rapide que la premiere fois, avec: 

`$ ./freezly.py relogin <password>`

Cette variante de login ne necessite pas l'envoi de SMS de confirmation. Si ca ne fonctionne pas, il faut repasser par la procedure de login classique (login + activation).
