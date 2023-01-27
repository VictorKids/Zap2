import socket
import select
import json

class Client:
    def __init__(self, username, password, _socket):
        self.username = username
        self.password = password
        self.socket   = _socket
        self.online   = True
        self.msgs     = []

# dictionary of <socket>:<client username>
Sockets = {}
# dictionary of <username>:<Client>
Clients = {}
# messages fixed size header length  -----------------> VOU MUDAR DEPOIS 
HEADER_LENGTH = 16


def accept_client(listening_socket, sockets_list):
    # accept the new connection, gettering information about the new client
    _client_socket, _client_address = listening_socket.accept()
    # receve initial data from client
    username, login_confirmation = login(_client_socket)
    # if an error occurs and no data is sent just ignore it 
    if login_confirmation == False:
        # close the connection with the user due to an error
        _client_socket.close()
        return True, _
    # add the new socket to the socket list to be managed by the select function
    sockets_list.append(_client_socket)
    print(f"accepting connection from{_client_address[0]}:{_client_address[1]}, username:{username}")
    return False, username


def make_header(message_body):
    return f'{len(message_body):<HEADER_LENGTH}'


def send_message(username, origin, msg):
    tmp_json = json.dumps({"destin": username, "origin": origin, "message_body": msg})
    Clients[username].socket.send(bytes(make_header(tmp_json) + (tmp_json), "utf-8"))


def login(client_socket):
    # receive only the header of the message
    message_header = client_socket.recv(HEADER_LENGTH)
     # if the header is empty, it means the connection should end
    if not len(message_header):
        return False
    # convert the information in the header
    message_length = int(message_header.decode("utf-8").strip())
    # receive the user's username and password
    username_and_password = client_socket.recv(message_length)
    # manipulate the data received to the intended format 
    [username, password] = username_and_password.decode("utf-8").split("@")
    # in case the username already exists
    if username in Clients:
        # if the account is not being used now
        if Clients[username].online == False:
            # check if the password is correct
            if Clients[username].password == password:
                # if true, set the user as online, link the socket to the username and return a confirmation message
                Clients[username].online = True
                Clients[username].socket = client_socket
                Sockets[client_socket] = username
                client_socket.send(bytes("Success", "utf-8"))
            # if not, notified it back to the client
            else:
                client_socket.send(bytes("Invalid Password", "utf-8"))
                return _, False
        # if the account is in use already, deny the login
        else:
            client_socket.send(bytes(f"{username} is already connected", "utf-8"))
            return _, False
    # in case the username does not exists
    else:
        # create a new user to the server
        Clients[username] = Client(username, password, client_socket)
        Sockets[client_socket] = username
    # the login was a success
    return username, True


def logout(username):
    # reference to the target socket
    to_del_socket = Clients[username].socket
    # remove the socket from the select management list
    sockets_list.remove(to_del_socket)
    # undo the link between socket and username
    del Sockets[to_del_socket]
    Clients[username].socket = None
    # set the client as offline
    Clients[username].online = False



def receive_message(client_socket):
    try:
        # receive only the header of the message
        message_header = client_socket.recv(HEADER_LENGTH)
        # if the header is empty, it means the connection should end
        if not len(message_header):
            return False
        # convert the information in the header
        message_length = int(message_header.decode("utf-8").strip())
        # return the message header separeted from the message body
        return {"header": message_header, "data": client_socket.recv(message_length)}
    # in case of something goes wrong, a error message is displayed to the server terminal and the program continues
    except:
        print("[ERROR] MESSAGE RECEIVE ERROR [ERROR]")
        return False


# defining in which IP and PORT the server is running 
IP   = socket.gethostname()
PORT = 1999
# creating the socket that will handle new connections from clients
listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# configuring the socket to reuse the local address (whatever it means)
listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# binding the IP and PORT to the socket
listening_socket.bind((IP, PORT))
print(socket.gethostname())
# a non-blocking wait for new connections
listening_socket.listen()
# list of socket to be monitored by the select function
sockets_list = [listening_socket]
# server main loop, where the check for new connections and messages happens
while True:
    # select function manages the multiple events that can occur to the sockets passed as parameters
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    # for those sockets where there is a event to be handle
    for notified_socket in read_sockets:
        # if the event is a new connection 
        if notified_socket == listening_socket:
            # calls the acception handle function
            login_flag, _username = accept_client(listening_socket, sockets_list)
            # check if no errors occured
            if login_flag:
                # if an error occurs, skip this iteration 
                continue
        # if an old client login, check if there is no messages to be delivery
        if Clients[_username].msgs != []:
            # if there is, send each one in order
            for indexed_message, index_origin in Clients[_username].msgs:
                send_message(Clients[_username].username, index_origin, indexed_message)
        # if the event is a message from a knowed client
        else:
            # receive the message
            message = receive_message(notified_socket)
            # check for message validation
            if message == False:
                # if the message is invalide, report it and close the connection
                print(f"Closing connection with {notified_socket} due to an error")
                logout(Sockets[notified_socket])
                continue
            # convert the message data from json to a dictionary
            message = json.load(message["data"])
            # get the destin user and the message
            destin = message["destin"]
            origin = message["origin"]
            message_body = message["body"]
            # check if the user is online
            if Clients[destin].online == True:
                # if true, send the message
                send_message(destin, origin, message_body)
            else:
                # if false, save the message for when the client login
                Clients[destin].msgs.append((message_body, origin))

