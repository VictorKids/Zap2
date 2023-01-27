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

HEADER_LENGTH = 16


def accept_client(listening_socket, sockets_list):
    # accept the new connection, gettering information about the new client
    # if an error occurs and no data is sent and close the connection with the user
    # if not, add the new socket to the socket list to be managed by the select function
    _client_socket, _client_address = listening_socket.accept()
    username, login_confirmation = login(_client_socket)
    if login_confirmation == False:
        _client_socket.close()
        return True, _
    sockets_list.append(_client_socket)
    print(f"accepting connection from{_client_address[0]}:{_client_address[1]}, username:{username}")
    return False, username


def make_header(message_body):
    # build the header of a given message
    return f'{len(message_body):<HEADER_LENGTH}'


def send_message(username, origin, msg):
    # convert the message to a json and then send it to client after concatenate the header with the body
    tmp_json = json.dumps({"destin": username, "origin": origin, "message_body": msg})
    Clients[username].socket.send(bytes(make_header(tmp_json) + (tmp_json), "utf-8"))


def login(client_socket):
    # receive only the header of the message
    # if the header is empty, it means the connection should end
    # else, convert the information in the header
    # then receive the user's username and password
    # manipulate the data received to the intended format 
    message_header = client_socket.recv(HEADER_LENGTH)
    if not len(message_header):
        return False
    message_length = int(message_header.decode("utf-8").strip())
    username_and_password = client_socket.recv(message_length)
    [username, password] = username_and_password.decode("utf-8").split("@")
    # in case the username already exists
    # if the account is not being used now
    # check if the password is correct
    #  if true, set the user as online, link the socket to the username and return a confirmation message
    #  if false, notified it back to the client
    # if the account is in use already, deny the login
    # in case the username does not exists
    #  create a new user to the server
    if username in Clients:
        if Clients[username].online == False:
            if Clients[username].password == password:
                Clients[username].online = True
                Clients[username].socket = client_socket
                Sockets[client_socket] = username
                client_socket.send(bytes("Success", "utf-8"))
            else:
                client_socket.send(bytes("Invalid Password", "utf-8"))
                return _, False
        else:
            client_socket.send(bytes(f"{username} is already connected", "utf-8"))
            return _, False
    else:
        Clients[username] = Client(username, password, client_socket)
        Sockets[client_socket] = username
    return username, True


def logout(username):
    # create a reference to the target socket
    # remove the socket from the select management list
    # undo the link between socket and username
    # and set the client as offline
    to_del_socket = Clients[username].socket
    sockets_list.remove(to_del_socket)
    del Sockets[to_del_socket]
    Clients[username].socket = None
    Clients[username].online = False



def receive_message(client_socket):
    # first, receive only the header of the message
    # if the header is empty, it means the connection should end
    # else, convert the information in the header
    # return, separating the message header from the message body
    # in case of something goes wrong, a error message is displayed to the server terminal and the program continues
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode("utf-8").strip())
        return {"header": message_header, "data": client_socket.recv(message_length)}
    except:
        print("[ERROR] MESSAGE RECEIVE ERROR [ERROR]")
        return False


# defining in which IP and PORT the server is running 
IP   = socket.gethostname()
PORT = 1999
# creating the socket that will handle new connections from clients
# configuring the socket to reuse the local address (whatever it means)
# binding the IP and PORT to the socket
# set a non-blocking wait for new connections
listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listening_socket.bind((IP, PORT))
print(socket.gethostname())
listening_socket.listen()
# list of socket to be monitored by the select function
sockets_list = [listening_socket]
# server main loop
# where the check for new connections and messages happens
while True:
    # select function manages the multiple events that can occur to the sockets passed as parameters
    # iterate on those sockets where there is a event to be handle
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        # if the event is a new connection 
        # calls the acception handle function
        # check if no errors occured
        # if an error occurs, skip this iteration 
        # if not, procede the function
        # if an old client login, check if there is no messages to be delivery
        # if there is, send each one in order
        if notified_socket == listening_socket:
            login_flag, _username = accept_client(listening_socket, sockets_list)
            if login_flag:
                continue
            if Clients[_username].msgs != []:
                for indexed_message, index_origin in Clients[_username].msgs:
                    send_message(Clients[_username].username, index_origin, indexed_message)
        # if the event is a message from a knowed client
        # receive the message
        # check for message validation
        # if the message is invalid, report it and close the connection
        #if not, convert the message data from json to a dictionary
        # get the destin user, origin user and the message
        # check if the user is online
        # if true, send the message
        # if false, save the message for when the client login
        else:
            message = receive_message(notified_socket)
            if message == False:
                print(f"Closing connection with {notified_socket} due to an error")
                logout(Sockets[notified_socket])
                continue
            message = json.load(message["data"])
            destin = message["destin"]
            origin = message["origin"]
            message_body = message["body"]
            if Clients[destin].online == True:
                send_message(destin, origin, message_body)
            else:
                Clients[destin].msgs.append((message_body, origin))

