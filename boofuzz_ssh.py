from boofuzz import *
import sys

host = sys.argv[1]
port = int(sys.argv[2])

#def banner(target, fuzz_data_logger, session, *args, **kwargs):
#    target.send(b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\x0d\x0a")
#    data = target.recv(1024)
#    print("RECV: %s" % str(data))

#session = Session(target=Target(SocketConnection(host, int(port))), pre_send_callbacks=[banner,])
session = Session(target=Target(SocketConnection(host, int(port))))


s_initialize(name="BinaryPacket")
s_bytes(b"\x00\xff\xff\xff", size=4, name="packet_length")
s_static("\x00", name="padding_length")
s_string("A"*1000, name="payload")
s_bytes(b"\x00", max_len=255, name="random_padding")
s_string("A"*100, name="mac")

s_initialize(name="ProtocolVersionExchange")
s_static("SSH-")
s_string("2.0",name="protoversion")
s_static("-")
s_string("FUZZ", name="softwareversion")
s_static(" ")
s_string("FUZZ", name="comments")
s_static("\r\n")

s_initialize(name="KeyExchangeInitClient")
s_size("KeyExchangeInit", length = 4, endian=">", fuzzable=False)
if s_block_start("KeyExchangeInit"):
    s_static("\x04", name="padding length")
    s_static("\x14", name="SSH_MSG_KEXINIT") #message code: key exchange init
    s_bytes(b"0123456789ABCDEF", size=16, name="cookie")
    # Algorithms
    s_size("kex_algorithms", endian=">", fuzzable=False)
    if s_block("kex_algorithms"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("server_host_key_algorithms", endian=">", fuzzable=False)
    if s_block("server_host_key_algorithms"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("encryption_algorithm_client_to_server", endian=">", fuzzable=False)
    if s_block("encryption_algorithm_client_to_server"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("encryption_algorithms_server_to_client", endian=">", fuzzable=False)
    if s_block("encryption_algorithms_server_to_client"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("mac_algorithms_client_to_server", endian=">", fuzzable=False)
    if s_block("mac_algorithms_client_to_server"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("mac_algorithms_server_to_client", endian=">", fuzzable=False)
    if s_block("mac_algorithms_server_to_client"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("compression_algorithms_client_to_server", endian=">", fuzzable=False)
    if s_block("compression_algorithms_client_to_server"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("compression_algorithms_server_to_client", endian=">", fuzzable=False)
    if s_block("compression_algorithms_server_to_client"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("languages_client_to_server", endian=">", fuzzable=False)
    if s_block("languages_client_to_server"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_size("languages_server_to_client", endian=">", fuzzable=False)
    if s_block("languages_server_to_client"):
        s_string("FUZZIIIIIIING")
    s_block_end()
    s_static("\x00\x00\x00\x00\x00\x00\x00\x00\x00")
s_block_end()


session.connect(s_get("BinaryPacket"))
session.connect(s_get("ProtocolVersionExchange"))
session.connect(s_get("ProtocolVersionExchange"), s_get("KeyExchangeInitClient"))
session.fuzz()
