#!/usr/bin/env python3
from datetime import datetime
import traceback
from enum import Enum
import logging.config
import sys
import re
from hashlib import sha1
from zeep import Client
import hmac
from binascii import hexlify,unhexlify
import struct
import base64
import xml.etree.ElementTree as etree
import pickle

#user-configurable area
AUTH_FILE="authstate.dat" #file storing authentication state
DEBUG=False
TRACE=False


#exceptions
class IzlyError(Exception):
    pass

class LogonFailure(IzlyError):
    pass

# for debugging
def enable_trace():
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })

# Signature-generating function helpers
def izly_auth(activation, counter): 
    hashed = hmac.new(base64.b64decode(activation), struct.pack(">Q", counter), sha1)
    s = base64.b64encode(hashed.digest()).decode("ascii")
    s = re.sub("\+", "-", s)
    s = re.sub("\/", "_", s)
    return s

def izly_pay(userid, session_id, cardid, amount, otp):
    message = userid + "," + session_id + "," + cardid + "," + amount + "," + otp
    hashed = hmac.new(otp.encode("ascii"), message.encode("ascii"), sha1)
    s = base64.b64encode(hashed.digest()).decode("ascii")
    s = re.sub("\+", "-", s)
    s = re.sub("\/", "_", s)
    return s

#object representing authentication state (persisted into "pickle" file)
class AuthState(object):
    def __init__(self, counter=0):
        self.user = None
        self.token = None
        self.counter = counter
        self.session_id = None
        self.act_code = None

    def ensure_logon_step1_done(self):
        if self.act_code is None:
            raise ValueError

    def ensure_logon_step2_done(self):
        if self.token is None:
            raise ValueError

#izly client (network layer)
#l'objet IzlyClient contient une methode generique req() pour la plupart des requetes
#les requetes necessitant un traitement specifique (do_login_XXXX) sont implementees par des methodes specifiques
#le membre auth_state contient l'etat d'authentification qui est persiste dans authstate.dat via pickle
class IzlyClient(object):
    def __init__(self, url, debug=DEBUG, trace=TRACE):
        self.url = url
        self.debug = debug
        if trace:
            enable_trace()

    def dbg(self, *args, **kwargs):
        if self.debug:
            print(*args, **kwargs)


    def dump(self, tree, indent=0):
        if (indent == 0):
            print("Resultat de la requete SOAP: ")
        print(indent * " " + tree.tag)
        for k in sorted(tree.keys()):
            print(indent *  " " + k + " --> " + tree.get(k))
        if (tree.text is not None):
            print(indent * " " + "valeur: " + tree.text)
        for i in tree:
            self.dump(i, indent + 2)

    def connect_soap(self):
        self.client = Client(self.url)

    def req(self, name, **kwargs):
        self.auth_state.ensure_logon_step2_done()
        self.client.transport.session.headers.update({'Authorization': 'Bearer ' + self.auth_state.token})
        dic = {**kwargs, **{"userId": self.auth_state.user, "model": "A", "format": "T", "channel": "AIZ", "version": "6.0", "sessionId": self.auth_state.session_id}}
        self.dbg("REQUEST: " + name + " with args " + str(dic))
        response = self.client.service.__getattr__(name)(**dic)
        if response is not None:
            self.dbg("RESPONSE: " + response)
        xml = etree.fromstring(response)
        if xml.find("Error") is not None:
            self.dbg("ERROR: " + xml.find("Msg").text)
            raise IzlyError(xml.find("Msg").text)
        return response

    def do_logon_step1(self, phone, pw):
        result = self.client.service.Logon(user=phone,
            password=pw,
            smoneyClientType="PART", 
            rooted=0, model="A", 
            format="T", 
            channel="AIZ")
        xml = etree.fromstring(result)
        if xml.find("Error") is not None:
            self.dbg("ERROR: " + xml.find("Msg").text)
            raise LogonFailure(xml.find("Msg").text)
        self.auth_state.user = phone
        return xml

    def do_logon_simple(self, pw):
        otp = self.get_otp()
        result = self.client.service.Logon(user=self.auth_state.user,
            password=pw,
            passOTP=pw + otp,
            smoneyClientType="PART", 
            rooted=0, model="A", 
            format="T", 
            channel="AIZ")
        xml = etree.fromstring(result)
        if xml.find("Error") is not None:
            self.dbg("ERROR: " + xml.find("Msg").text)
            raise LogonFailure(xml.find("Msg").text)
        self.auth_state.session_id = xml.find("SID").text
        self.auth_state.token = xml.find("OAUTH").find("ACCESS_TOKEN").text
        self.dbg("Session id:" + self.auth_state.session_id)
        self.dbg("Token:" + self.auth_state.token)
        return result

    def get_otp(self):
        otp = izly_auth(self.auth_state.act_code, self.auth_state.counter)
        self.auth_state.counter += 1
        return otp

    def save(self):
        pickle.dump(self.auth_state, open(AUTH_FILE, "wb"))

    def do_logon_step2(self):
        self.auth_state.ensure_logon_step1_done()
        otp = self.get_otp()
        result = self.client.service.Logon(user=self.auth_state.user,
            passOTP=otp, 
            password="",
            smoneyClientType="PART", 
            rooted=0, model="A", 
            format="T", 
            channel="AIZ")
        xml = etree.fromstring(result)
        if xml.find("Error") is not None:
            self.dbg("ERROR: " + xml.find("Msg").text)
            raise LogonFailure(xml.find("Msg").text)
        self.auth_state.session_id = xml.find("SID").text
        self.auth_state.token = xml.find("OAUTH").find("ACCESS_TOKEN").text
        self.dbg("Session id:" + self.auth_state.session_id)
        self.dbg("Token:" + self.auth_state.token)

    def do_confirm(self, idcarte, montant, pw):
        otp = self.get_otp()
        pr = izly_pay(self.auth_state.user, self.auth_state.session_id, idcarte, montant, pw + otp)
        return self.req("MoneyInCbConfirm", amount=montant, cardId=idcarte, print=pr, passOTP=pw + otp)

class CmdFlag(Enum):
    NONE = 0,
    ACT_CODE = 1, #la commande a besoin que le code d'activation soit connu
    SESSION = 2, #la commande a besoin d'une session active
    USES_SOAP = 3, #la commande emet une requete SOAP
   
class Command(object):
    def __init__(self, f, flags):
        self.f = f
        self.flags = flags

    def call(self, *args):
        obj = args[0]
        try:
            auth_state = pickle.load(open(AUTH_FILE, "rb"))
            print("Loaded existing auth state for: " + auth_state.user)
        except:
            auth_state = AuthState()
            print("Using new auth state")
        print("Telephone: " + str (auth_state.user))
        print("Compteur: " + str (auth_state.counter))
        print("Activation code: " + str(auth_state.act_code))
        print("Auth bearer token: " + str(auth_state.token))
        print("Session ID: " + str(auth_state.session_id))
        print("")
        obj.ic.auth_state = auth_state

        if (CmdFlag.ACT_CODE in self.flags) and (obj.ic.auth_state.act_code is None):
            raise ValueError("L'operation demande un code d'activation.")

        if (CmdFlag.SESSION in self.flags) and (obj.ic.auth_state.token is None):
            raise ValueError("L'operation demande une session active.")

        if (CmdFlag.USES_SOAP in self.flags):
            obj.ic.connect_soap()

        return self.f(*args)


### La partie interface utilisateur

def cmd(flags):
    def aux(f):
        return Command(f, flags)
    return aux

#izly client (interface layer)
#gere les commandes utilisateur, et appelle l'objet IzlyClient pour les realiser 
class CmdInterface(object):
    def __init__(self, ic):
        self.ic = ic #l'objet IzlyClient contient le client SOAP et l'etat d'authentification

    def process(self, args):
        attr = None
        if hasattr(self, args[0]):
            attr = getattr(self, args[0])
        if (attr is not None) and (isinstance(attr, Command)):
            attr.call(self, *args[1:])
        else:
            raise Exception("Unknown command: " + args[0])

    @cmd({CmdFlag.USES_SOAP})
    def login(self, phone, pw):
        print("Clearing auth state.")
        self.ic.auth_state = AuthState()
        self.ic.do_logon_step1(phone, pw)
        self.ic.save()

    @cmd({CmdFlag.USES_SOAP})
    def activation(self, code):
        self.ic.auth_state.act_code = code
        self.ic.auth_state.token = None
        self.ic.auth_state.session_id = None
        self.ic.auth_state.counter = 0
        self.ic.do_logon_step2()
        self.ic.save()

    @cmd({CmdFlag.ACT_CODE, CmdFlag.USES_SOAP})
    def relogin(self, pw):
        response = self.ic.do_logon_simple(pw)
        self.ic.dump(etree.fromstring(response))
        self.ic.save()

    @cmd({})
    def status(self):
        pass

    @cmd({CmdFlag.SESSION, CmdFlag.USES_SOAP})
    def listecb(self):
        response = self.ic.req("MoneyInCbCbList")
        self.ic.dump(etree.fromstring(response))

    @cmd({CmdFlag.SESSION, CmdFlag.USES_SOAP})
    def historique(self):
        response = self.ic.req("GetStatement", filter="-1", nbItems="0", firstId="-1")
        self.ic.dump(etree.fromstring(response))

    @cmd({CmdFlag.SESSION, CmdFlag.USES_SOAP})
    def recharger(self, idcarte, montant):
        response = self.ic.req("MoneyInCb", amount=montant, cardId=idcarte)
        self.ic.dump(etree.fromstring(response))

    @cmd({CmdFlag.SESSION, CmdFlag.USES_SOAP})
    def confirmer(self, idcarte, montant, pw):
        response = self.ic.do_confirm(idcarte, str(float(montant)), pw)
        self.ic.dump(etree.fromstring(response))
        self.ic.save()

### Le programme principal

if len(sys.argv) < 2:
    print("""Commandes disponibles: 
./freezly.py status
    Donne le status d'authentification (telephone, presence du code d'activation et token, etc...)

./freezly.py login <telephone> <password>
    1ere phase d'authentification. Cela provoque l'envoi d'un code par SMS.
    On utilise ensuite la commande "activation" pour faire la 2eme phase.

./freezly.py activation <code d'activation>
    2eme phase d'authentification. On renseigne le code d'activation par SMS.
    Le code d'activation est la derniere partie de l'URL (apres le derner /) recu par SMS

./freezly.py relogin <password>
    Permet de se re-authentifier, pour "rafraichir" la session lorsqu'elle a expiree.
    On doit donner seulement le password. 
    Ne pas confondre avec la commande "login" qui est a utiliser lors de la premiere authentification.

./freezly.py historique
    Affiche la liste des paiements/rechargements effectues.

./freezly.py listecb
    Liste les cartes bancaires enregistrees dans le compte, avec leurs identifiants (id carte).

./freezly.py recharger <id carte> <montant>
    Lance le rechargement du compte a partir d'une carte bancaire enregistree.
    Il faut ensuite utiliser la commande "confirmer".

./freezly.py confirmer <id carte> <montant> <password>
    Confirme le rechargement du compte a partir de la carte bancaire.
    
AVERTISSEMENT : Cet outil est un simple exemple de demonstration pour illustrer la documentation du protocole. Il n'est pas prevu pour etre utilise en situation reelle. Il a ete realise a partir d'informations obtenues par reverse-engineering, donc potentiellement incompletes ou inexactes. Il a ete tres peu teste, il contient probablement des bugs, qui peuvent entrainer des consequences facheuses pour votre ordinateur, votre compte Izly, vos informations bancaires, etc...""")
    sys.exit(1)

ic = IzlyClient("https://soap.izly.fr/Service.asmx?WSDL")

cli = CmdInterface(ic)
try:
    cli.process(sys.argv[1:])
    print("La commande a reussi")
except:
    traceback.print_exc()
    print("La commande a echouee, pour la raison mentionee ci-dessus.")
    sys.exit(1)

sys.exit(0)


