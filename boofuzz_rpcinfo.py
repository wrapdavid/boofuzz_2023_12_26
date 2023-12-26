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
s_bytes(a:=bytearray.fromhex("8000002834e3cd790000000000000002000186a0000000030000000400000000000000000000000000000000"), size=len(a), name="packet_length")
s_static("\x00", name="padding_length")
s_string("A"*1000, name="payload")
s_bytes(b"\x00", max_len=255, name="random_padding")
s_string("A"*100, name="mac")


session.connect(s_get("BinaryPacket"))
session.fuzz()
