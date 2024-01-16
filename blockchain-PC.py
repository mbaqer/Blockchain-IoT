from time import strftime
import time, os, threading
from tkinter import *
from tkinter import ttk
import tkinter.simpledialog as simpledialog
import tkinter.messagebox as messagebox
import tkinter.filedialog as filedialog
from pathlib import Path
from CPABSC_Hybrid_R import *
from definitions import *
from random import SystemRandom
from uuid import uuid4
import requests
from flask import Flask, jsonify, request
from pyclamd import *
import base64

# We will mine automatically every 15 seconds and then propagate blockchain with other nodes
# Working, need to connect with Blockchain First!
def periodic_spread():
    while True:
        time.sleep(15)
        print("INFO: Waiting for transactions...")
        verify_block_action(blockchain.current_transactions, None, None, None)

        if blockchain.connected and not blockchain.chain_updated:
            print("INFO: Getting Blockchain...")
            blockchain.resolve_conflicts()
            blockchain.chain_updated = True

# Definition to run the Flask Framework in a separated thread from Tkinter
def init_blockchain():
    blockchain_spread.start()
    app.app_context()
    app.run(host='0.0.0.0', port=5000)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Keys Generation
groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)
hyb_abe = HybridABEnc(cpabe, groupObj)

# access_policy = '((four or three) and (three or one))'
# S = ['ONE', 'TWO', 'THREE']

access_policy = '(ONE and TWO) or (THREE and (FOUR and FIVE))' # 5
S = ['ONE', 'TWO'] # 2

(pk, msk) = hyb_abe.setup()
(sk, k_sign) = hyb_abe.keygen(pk, msk, S)

pkpath = Path("pk.txt")
mskpath = Path("msk.txt")
skpath = Path("sk.txt")
k_signpath = Path("k_sign.txt")

if pkpath.is_file():
    print("Reading File pk.txt")
    pk_read = open("pk.txt", 'r')
    pk_str = pk_read.read() # it's a string
    pk_bytes = pk_str.encode("utf8")
    pk = bytesToObject(pk_bytes, groupObj)
    pk_read.close()

else:
    print("Writing file File pk.txt")
    pk_read = open("pk.txt", 'w')
    pk_read.write(str(objectToBytes(pk, groupObj), 'utf-8'))  # saving as a string
    pk_read.close()

if mskpath.is_file():
    print("Reading File msk.txt")
    msk_read = open("msk.txt", 'r')
    msk_str = msk_read.read() # it's a string
    msk_bytes = msk_str.encode("utf8")
    msk = bytesToObject(msk_bytes, groupObj)
    msk_read.close()

else:
    print("Writing file File msk.txt")
    msk_read = open("msk.txt", 'w')
    msk_read.write(str(objectToBytes(msk, groupObj), 'utf-8'))  # saving as a string
    msk_read.close()

if skpath.is_file():
    print("Reading File sk.txt")
    sk_read = open("sk.txt", 'r')
    sk_str = sk_read.read()  # it's a string
    sk_bytes = sk_str.encode("utf8")
    sk = bytesToObject(sk_bytes, groupObj)
    sk_read.close()

else:
    print("Writing file File sk.txt")
    sk_read = open("sk.txt", 'w')
    sk_read.write(str(objectToBytes(sk, groupObj), 'utf-8'))  # saving as a string
    sk_read.close()

if k_signpath.is_file():
    print("Reading File sk.txt")
    k_sign_read = open("k_sign.txt", 'r')
    k_sign_str = k_sign_read.read()  # it's a string
    k_sign_bytes = k_sign_str.encode("utf8")
    k_sign = bytesToObject(k_sign_bytes, groupObj)
    k_sign_read.close()

else:
    print("Writing file File sk.txt")
    k_sign_read = open("k_sign.txt", 'w')
    k_sign_read.write(str(objectToBytes(k_sign, groupObj), 'utf-8'))  # saving as a string
    k_sign_read.close()
# Keys Generation End ========== x ==========

# print("INFO pk: ", pk)
keys_generation_time = time.time()
print("INFO: Node Identifier:" + node_identifier)

# Instantiate the Blockchain
blockchain = Blockchain()
blockchain_thread = threading.Thread(name="blockchain", target=init_blockchain, daemon=True)

#Node List and Chain Loading...
blockchain.load_values() # From definitions

# Instantiate the Node
app = Flask(__name__)

# Other separated thread to mining and sharing blockchain periodically
blockchain_spread = threading.Thread(name="spread", target=periodic_spread, daemon=True)

@app.route('/blocks/new', methods=['POST'])
def blocks_new():
    values = request.values

    # Create a new Block
    added = blockchain.new_block(_transactions=values)
    if added:
        response = {
            'message': 'The block is added to the chain',
        }
    else:
        response = {
            'message': 'The block was rejected',
        }
    return jsonify(response), 201
    
@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block

    if len(blockchain.current_transactions) <= 0:
        response = {
            'message': 'No transactions to validate'
        }
        return jsonify(response), 200

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)

    block = blockchain.new_block(previous_hash)
    if block == False:
        response = {
            'message': "Invalid Transaction!",
        }
        return jsonify(response), 400
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():   # from Definition
    values = request.get_json()
    values = request.values

    required = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['name'], values['file'], values['file_hash'],
                                       values['ct'], values['pi'], values['pk'])
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/transactions', methods=['GET'])
def transactions():
    response = {
        'chain': blockchain.current_transactions,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():  # From Definitions
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

def foo():
    print("foo action")

def disconnect_exit():
    blockchain.save_values() # From Definitions
    main_window.quit()

def add_node():
    _title = "Add new node"
    _node_address = simpledialog.askstring(_title, "Node Address:")
    if (blockchain.register_node(address = _node_address) == True):
        messagebox.showinfo(title=_title, message="Node added to node list:\nCurrent nodes: " + str(blockchain.nodes.__len__()))

def print_rpi():
    print(blockchain.rpis)

def add_rpi():
    _title = "Add new RPi"
    _node_address = simpledialog.askstring(_title, "RPi Address:")
    if (blockchain.register_rpi(address = _node_address) == True): # Definitions
        messagebox.showinfo(title=_title, message="RPi added to RPi list:\nCurrent RPis: " + str(blockchain.rpis.__len__()))

def _filepath_get(window, filename, filepath):
    file = filedialog.askopenfile(title="Select File")
    _filepath = file.name.split("/")
    _filename = _filepath[_filepath.__len__()-1]
    filename.set(_filename)
    filepath.set(file.name)
    window.lift()

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

# Will think about later!
def _upload_file(window, filepath, filename, text_keygen, text_keygentime, text_signedtime):
    _file = open(filepath, 'br').read()  # byte
    _file_str = base64.b64encode(_file).decode('ascii')
    timestamp = time.time()

    _file_hash = hashlib.sha256(_file).hexdigest()
    # print("INFO: File uploading: File hash: ", _file_hash)


    (ct, delta) = hyb_abe.encrypt(pk, k_sign, _file, access_policy)
    delta_bytes = objectToBytes(delta, groupObj)
    _pi = hashlib.sha256(_file).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()
    # print("INFO: File uploading: File hash (signed): ", _pi)

    _pk = str(objectToBytes(pk, groupObj), 'utf-8')
    _hash = hashlib.sha256(_file).hexdigest()
    _ct = str(objectToBytes(ct, groupObj), 'utf-8')

    _newblock = blockchain.new_transaction(filename, _file_str, _hash, _ct, _pi, _pk)

    # Fill form fields
    text_keygen.set(str(objectToBytes(pk,groupObj), 'utf-8'))
    text_keygentime.set(strftime('%x %X', time.localtime(keys_generation_time)))
    text_signedtime.set(strftime('%x %X', time.localtime(timestamp))) # Will think about it later

    messagebox.showinfo("File Upload", "The transaction has been correctly created.\n It will be included in block " + str(_newblock))
    window.lift()

# Tough things
def verify_block_action(current_transaction, text_keygen_time, text_sign_verif_time, text_block_creation_time):
    if len(current_transaction) <= 0:
        return False
    transaction = current_transaction.pop(0)

    if not blockchain.valid_file(transaction): # From definitions
        print("verify_block_action: valid_file is False")
        return False

    _file = transaction['file']
    _filename = transaction['name']
    _hash = transaction['file_hash']

    if text_keygen_time is not None:
        text_keygen_time.set(strftime('%x %X', time.localtime(keys_generation_time)))
    if text_sign_verif_time is not None:
        text_sign_verif_time.set(strftime('%x %X', time.localtime(time.time())))
    if text_block_creation_time is not None:
        text_block_creation_time.set(strftime('%x %X', time.localtime(time.time())))

    (ct, delta) = hyb_abe.encrypt(pk, k_sign, _file, access_policy)
    delta_bytes = objectToBytes(delta, groupObj)
    type(ct)
    type(delta_bytes)
    _pi = hashlib.sha256(bytes(str(_file), 'utf-8')).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

    _pk = str(objectToBytes(pk, groupObj), 'utf-8')
    _ct = str(objectToBytes(ct, groupObj), 'utf-8')

    blockchain.current_transactions.insert(0,{
        'name': _filename,
        'file': _file,
        'file_hash': _hash,
        'ct': _ct,
        'pi': _pi,
        'pk': _pk
    })

    #Block Creation # Defination
    blockchain.new_block(blockchain.last_block['previous_hash']) # new_block >> from Definition

# Need to understand how things are sending to RPi.
def send_update_button_click(file_name):
    print("INFO - Retrieving data for file " + file_name)
    values = {}
    #Get block number to send it to RPis
    for blocks in blockchain.chain:
        for trans in blocks['transactions']:
            if trans['name'] == file_name:
                print("INFO - File found in block " + str(blocks['index']))
                values['name'] = trans['name']
                values['file'] = trans['file']
                values['file_hash'] = trans['file_hash']
                values['ct'] = trans['ct']
                values['pi'] = trans['pi']
                values['pk'] = trans['pk']

    if len(blockchain.rpis)<=0:
        print("ERROR - There are no RPis registered!")
    for rpi_address in blockchain.rpis:
        print("INFO - Sending " + values['name'] + " to RPi " + rpi_address)
        blockchain.send_updates(rpi_address, values['name'], values['file'], values['file_hash'],
                                values['ct'], values['pi'], values['pk']) # send_updates >> from Defination

# Sending Updates to RPi, can we send sk seprately and save the sk at RPi?
# Need to understand how it's working.
def send_update():
    window_su = Toplevel()
    window_su.title = "Disseminate Messages to RPIs"
    window_su.geometry("400x100")

    label = Label(window_su, text="Select the file:").place(x=_column(1), y=_line(1))

    #Define Combobox with its values
    files = blockchain.get_file_names() # from Definitions
    cb = ttk.Combobox(window_su, values=files)
    cb.place(x=_column(2), y=_line(1))

    button_send = Button(window_su, text="Send", command=lambda: send_update_button_click(cb.get())).place(x=_column(3)-15, y=_line(2))

# def verify_software():
def verify_file():
    if len(blockchain.current_transactions) <= 0:
        messagebox.showinfo("Verify the Files","There are no Files in Transactions")
        return False

    window_vs = Toplevel()
    window_vs.title = "Verify Transactions Manually"
    window_vs.geometry("300x200")

    text_keygen_time = StringVar()
    label_keygen_time = Label(window_vs, text="KeyGen Timestamp:").place(x=_column(1), y=_line(1))
    entry_keygen_time = Entry(window_vs, textvariable=text_keygen_time).place(x=_column(2),y=_line(1))

    text_sign_verif_time = StringVar()
    label_sign_verif_time = Label(window_vs, text="Sign Timestamp:").place(x=_column(1), y=_line(2))
    entry_sign_verif_time = Entry(window_vs, textvariable=text_sign_verif_time).place(x=_column(2), y=_line(2))

    text_block_creation_time = StringVar()
    label_block_creation_time = Label(window_vs, text="BlockGen Timestamp:").place(x=_column(1), y=_line(3))
    entry_block_creation_time = Entry(window_vs, textvariable=text_block_creation_time).place(x=_column(2), y=_line(3))

    button_Mine = Button(window_vs, text="Verify Transactions",
                         command=lambda: verify_block_action(blockchain.current_transactions, text_keygen_time,
                                                             text_sign_verif_time, text_block_creation_time)).place(
        x=_column(3) - 85, y=_line(4))

# def upload_software():
def upload_file():
    windows_us = Toplevel()
    windows_us.title = "Message Upload"
    windows_us.geometry("300x200")

    text_filename = StringVar()
    label_filename = Label(windows_us, text="Message Name:").place(x=_column(1),y=_line(2))
    entry_filename = Entry(windows_us, textvariable=text_filename).place(x=_column(2), y=_line(2))

    text_filepath = StringVar()
    label_filepath = Label(windows_us, text="File Path:").place(x=_column(1), y=_line(1))
    entry_filepath = Entry(windows_us, textvariable=text_filepath).place(x=_column(2), y=_line(1))
    button_filepath = Button(windows_us, text="...", command=lambda: _filepath_get(windows_us, text_filename, text_filepath)).place(
        x=_column(3), y=_line(1)-4)

    text_keygentime = StringVar()
    label_keygentime = Label(windows_us, text="KeyGen Timestamp:").place(x=_column(1), y=_line(3))
    entry_filepath = Entry(windows_us, textvariable=text_keygentime).place(x=_column(2),y=_line(3))

    text_keygen = StringVar()
    label_keygen = Label(windows_us, text="Public Key:").place(x=_column(1), y=_line(4))
    entry_keygen = Entry(windows_us, textvariable=text_keygen).place(x=_column(2), y=_line(4))

    text_signedtime = StringVar()
    label_signedtime = Label(windows_us, text="Signed Timestamp:").place(x=_column(1), y=_line(5))
    entry_signedtime = Entry(windows_us, textvariable=text_signedtime).place(x=_column(2), y=_line(5))

    button_Send = Button(windows_us, text="Upload",
                         command=lambda: _upload_file(windows_us, text_filepath.get(), text_filename.get(), text_keygen,
                                                      text_keygentime, text_signedtime)).place(x=_column(2), y=_line(6))
    button_Cancel = Button(windows_us, text="Cancel", command=windows_us.quit).place(x=_column(3)-42, y=_line(6))

main_window = Tk()
main_window.title("Blockchain Based Message Dissemination System")
main_window.geometry("650x300")
def _create_main_window_structure():
    Menu_Bar = Menu(main_window)
    Connection_Menu = Menu(Menu_Bar, tearoff=0)
    Connection_Menu.add_command(label="Add node", command=add_node)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Add RPi", command=add_rpi)
    Connection_Menu.add_command(label="Print RPi list", command=print_rpi)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Connect Blockchain", command=blockchain_thread.start)
    Connection_Menu.add_command(label="Disconnect and Exit", command=disconnect_exit)
    Menu_Bar.add_cascade(label="Blockchain", menu=Connection_Menu)

    Actions_Menu = Menu(Menu_Bar, tearoff=0)
    Actions_Menu.add_command(label="Upload Messages (Make Transaction)", command=upload_file)
    Actions_Menu.add_command(label="Verify Transaction (Manually)", command=verify_file)
    Actions_Menu.add_command(label="Disseminate Messages to RPi (Targetted)", command=send_update)
    Actions_Menu.add_separator()
    Actions_Menu.add_command(label="Print Chain", command=blockchain.print_chain) # Defination
    Actions_Menu.add_command(label="Print Transactions", command=blockchain.print_transactions) # Defination
    Menu_Bar.add_cascade(label="Actions", menu=Actions_Menu)

    # Show menu
    main_window.config(menu=Menu_Bar)

_create_main_window_structure()

mainloop()