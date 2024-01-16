from tkinter import *
from CPABSC_Hybrid_R import *
import os
from flask import Flask, jsonify, request
from uuid import uuid4
import threading
import hashlib
import base64
import subprocess
import urllib.parse

app = Flask(__name__)

groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)
hyb_abe = HybridABEnc(cpabe, groupObj)

def start_listening():
    app.app_context()
    app.run(host='0.0.0.0', port=5001)

@app.route('/ping', methods=['GET'])
def transactions():
    response = {
        'message': "PONG!",
    }
    return jsonify(response), 200

def install_sw(name, ct, pk, sk, pi, file):
    (file_pr_, delta_pr) = hyb_abe.decrypt(pk, sk, ct)
    file_pr = base64.b64decode(file_pr_).decode('ascii')

    print("Writing Received Message: " + str(name))
    cur_directory = os.getcwd()
    file_path = os.path.join(cur_directory, name)
    open(file_path, 'w').write(file_pr)

    delta_bytes = objectToBytes(delta_pr, groupObj)
    pi_pr = hashlib.sha256(bytes(str(file), 'utf-8')).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

    print('-----------------------------------------------------------------------------------')

    if pi == pi_pr:

        print('Successfully Verified!')

        if os.name == "posix":
            os.chmod(file_path, 0o777)
        try:
            print("Running Files....")
            subprocess.call(file_path)
            print("The message has been reached!")
            print('-----------------------------------------------------------------------------------')
            return True

        except OSError as e:
            print("ERROR - The file is not a valid application: " + str(e))
            print('-----------------------------------------------------------------------------------')
            return False

    else:

        print('Verification Failed.. !!')
        print('-----------------------------------------------------------------------------------')
        return False


@app.route('/updates/new', methods=['POST'])
def post_updates_new():
    values = request.values

    required = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']

    # write ct
    print("Writing file as ct")
    ct_write = open("ct", 'w')
    ct_write.write(values['ct'])
    ct_write.close()

    # write pk
    print("Writing file as pk.txt")
    pk_write = open("pk.txt", 'w')
    pk_write.write(values['pk'])
    pk_write.close()

    name = values['name']
    file = values['file']
    file_hash = values['file_hash']

    pi = values['pi']

    ct_str = values['ct']
    ct_bytes = ct_str.encode("utf8")
    ct = bytesToObject(ct_bytes, groupObj)
    # print(ct)

    pk_str = values['pk']
    pk_bytes = pk_str.encode("utf8")
    pk = bytesToObject(pk_bytes, groupObj)

    if not all(k in values for k in required):
        return 'Missing values', 400

    print("Reading sk from saved file")
    sk_read = open("sk.txt", 'r')
    sk_str = sk_read.read()  # it's a string
    sk_bytes = sk_str.encode("utf8")
    sk = bytesToObject(sk_bytes, groupObj)
    sk_read.close()
    print("INFO - Received message...")
    # if pi == pi_pr
    # print("Successfully Signed.")
    if install_sw(name, ct, pk, sk, pi, file):
        return 'File reached!', 200
    else:
        return 'Failed!', 400

def _line(line):
    if line == 1:
        return 10
    else:
        return 10 + 30*(line-1)

def _column(col):
    if col == 1:
        return 10
    else:
        return 10 + 120*(col-1)

node_identifier = str(uuid4()).replace('-', '')

main_window = Tk()
main_window.title("Blockchain Based Message Dissemination - Smart Device Window")
main_window.geometry("600x250")
text_keygen_time = StringVar()
label_keygen_time = Label(main_window, text="Integrity Checking:").place(x=_column(1), y=_line(1))
entry_keygen_time = Entry(main_window, textvariable=text_keygen_time).place(x=_column(3)-35, y=_line(1))

listening_thread = threading.Thread(name="listening", target=start_listening, daemon=True)
listening_thread.start()
mainloop()