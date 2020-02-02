# mychap

An handmade chap challenge client made in c with raw udp socket.

Object-Oriented raw udp library is included :

Create new raw udp socket: socket = new_udp_socket("IP", PORT)
Write in it: socket->write(socket, {"DATA", DATA_SIZE})
Read in it: udp_data_t data = socket->read(socket)
Delete it: delete_udp_socket(socker)
