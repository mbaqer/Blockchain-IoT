
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.paddingschemes import PKCS7Padding
from charm.toolbox.securerandom import OpenSSLRand
from charm.core.crypto.cryptobase import MODE_CBC, AES, selectPRP
from charm.core.engine.util import objectToBytes, bytesToObject
import json
from base64 import b64encode, b64decode
from charm.core.math.pairing import hashPair as sha2
import hashlib

debug = False
class CPabe_BSW07(ABEnc):

    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    def setup(self):
        g1 = group.random(G1)
        g2 = group.random(G2)

        alpha = group.random(ZR)
        beta = group.random(ZR)
        g1.initPP(); g2.initPP()

        h = g1 ** beta
        f = g1 ** (1/beta)
        e_gg_alpha = pair(g1, g2 ** alpha)

        pk = {'g1': g1, 'g2': g2, 'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha}
        msk = {'beta': beta, 'g2_alpha': g2 ** alpha}
        return pk, msk

    def keygen(self, pk, msk, S):
        r_en = group.random()
        r_sn = group.random()

        g2_r_en = (pk['g2'] ** r_en)
        g2_r_sn = (pk['g2'] ** r_sn)
        D_en = (msk['g2_alpha'] * g2_r_en) ** (1 / msk['beta'])
        k_sign = (msk['g2_alpha'] * g2_r_sn) ** (1 / msk['beta'])
        k_ver = g2_r_sn

        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g2_r_en * (group.hash(j, G2) ** r_j)
            D_j_pr[j] = pk['g1'] ** r_j

        sk = {'D_en': D_en, 'Dj': D_j, 'Djp': D_j_pr, 'S': S, 'k_ver': k_ver}
        return sk, k_sign

    def encrypt(self, pk, k_sign, msg, access_policy):
        policy = util.createPolicy(access_policy)
        a_list = util.getAttributeList(policy)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)

        C_tilde = (pk['e_gg_alpha'] ** s) * msg
        C = pk['h'] ** s
        zeta = group.random(ZR)
        delta = pair(C, pk['g2'] ** zeta)
        pi = group.hash('delta' + 'msg')
        psi = (pk['g2'] ** zeta) * (k_sign ** pi)
        w = pk['g1'] ** s

        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g1'] ** shares[i]
            C_y_pr[i] = group.hash(j, G2) ** shares[i]

        ct = {'C_tilde': C_tilde, 'C': C, 'Cy': C_y, 'Cyp': C_y_pr,
              'access_policy': access_policy, 'attributes': a_list, 'w': w, 'psi': psi, 'pi': pi}
        return ct, delta

    def decrypt(self, pk, sk, ct):
        policy = util.createPolicy(ct['access_policy'])
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** z[j]

        A_tilde = pair(ct['C'], sk['D_en']) / A
        msg_pr = ct['C_tilde'] / A_tilde

        Cal_Num = pair(ct['C'], ct['psi'])
        Cal_Den1 = pair(ct['w'], sk['k_ver']) * A_tilde
        Cal_Den = Cal_Den1 ** ct['pi']
        delta_pr = Cal_Num / Cal_Den

        return msg_pr, delta_pr

class SymmetricCryptoAbstraction(object):
    def __init__(self, key, alg = AES, mode = MODE_CBC):
        self._alg = alg
        self.key_len = 16
        self._block_size = 16
        self._mode = mode
        self._key = key[0:self.key_len] # expected to be bytes
        assert len(self._key) == self.key_len, "SymmetricCryptoAbstraction key too short"
        self._padding = PKCS7Padding()

    def _initCipher(self,IV = None):
        if IV == None :
            IV =  OpenSSLRand().getRandomBytes(self._block_size)
        self._IV = IV
        return selectPRP(self._alg,(self._key,self._mode,self._IV))

    def __encode_decode(self,data,func):
        data['IV'] = func(data['IV'])
        data['CipherText'] = func(data['CipherText'])
        return data

    def _encode(self, data):
        return self.__encode_decode(data, lambda x: b64encode(x).decode('utf-8'))

    def _decode(self, data):
        return self.__encode_decode(data, lambda x: b64decode(bytes(x, 'utf-8')))

    def encrypt(self, message):
        #This should be removed when all crypto functions deal with bytes"
        if type(message) != bytes :
            message = bytes(message, "utf-8")
        ct = self._encrypt(message)
        #JSON strings cannot have binary data in them, so we must base64 encode cipher
        cte = json.dumps(self._encode(ct))
        return cte

    def _encrypt(self, message):
        #Because the IV cannot be set after instantiation, decrypt and encrypt
        # must operate on their own instances of the cipher
        cipher = self._initCipher()
        ct= {'ALG': self._alg,
            'MODE': self._mode,
            'IV': self._IV,
            'CipherText': cipher.encrypt(self._padding.encode(message))
            }
        return ct

    def decrypt(self, cipherText):
        f = json.loads(cipherText)
        return self._decrypt(self._decode(f))

    def _decrypt(self, cipherText):
        cipher = self._initCipher(cipherText['IV'])
        msg = cipher.decrypt(cipherText['CipherText'])
        return self._padding.decode(msg)

debug = False
class HybridABEnc(ABEnc):
    def __init__(self, scheme, groupObj):
        ABEnc.__init__(self)
        # check properties (TODO)
        self.abenc = scheme
        self.group = groupObj

    def setup(self):
        return self.abenc.setup()

    def keygen(self, pk, mk, object):
        return self.abenc.keygen(pk, mk, object)

    def encrypt(self, pk, k_sign, M, object):
        key = self.group.random(GT)
        (c1, delta) = self.abenc.encrypt(pk, k_sign, key, object)
        # instantiate a symmetric enc scheme from this key
        cipher = SymmetricCryptoAbstraction(sha2(key))
        c2 = cipher.encrypt(M)
        ct = {'c1':c1, 'c2':c2}
        return ct, delta

    def decrypt(self, pk, sk, ct):
        c1, c2 = ct['c1'], ct['c2']
        (key, delta_pr) = self.abenc.decrypt(pk, sk, c1)
        if key is False:
            raise Exception("failed to decrypt!")
        cipher = SymmetricCryptoAbstraction(sha2(key))
        msg_pr = cipher.decrypt(c2)
        return msg_pr, delta_pr