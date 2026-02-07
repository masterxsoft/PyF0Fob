from aut64 import aut64_unpack, aut64_decrypt, aut64_encrypt

AUT64_key = aut64_unpack(bytes.fromhex("038AA37B1E561F8384B619C52E0A3FD7"))

KEY1 = "C02F1BFC5C6D3650"
KEY2 = "C72B"

mask = 0b1111

print(" ")
print("------DECODE ORIGINAL ROLLING CODE SAMPLE------")
print(" ")
print("Decrypt:")
print("Key1: " + KEY1 + "  Key2: " + KEY2)
key = KEY1[2:21] + KEY2[0:2]

ct  = bytes.fromhex(key)
print("AUT64 Input: " + ct.hex(" ").upper())

pt = aut64_decrypt(AUT64_key, ct)
print("AUT64 Output: ", pt.hex(" ").upper())
serial = pt[0:4]        
counter = bytes([pt[5],pt[6],pt[4]]) 
last   = pt[7]           

print("fob sn:" + serial.hex().upper())
print("counter:" + counter.hex().upper())
print("last:", f"{last:02X}")
print("RAW-KEY: " + KEY1 + KEY2)

#--- increment counter & set unlock
print(" ")
print("------INCREMENT COUNTER + SET UNLOCK & GENERATE NEW CODE------")
print(" ")
print("Encrypt:")

newcnt = int.from_bytes(counter, "big") +1 #increment counter
newcnt = newcnt.to_bytes(3, 'big')
counter = newcnt
CMD = 1  #SET UNLOCK (1=unlock, 2=lock for Golf4 don't know why Fabia2007 is 0x0)
chk_sum = hex(CMD)[2:] + hex(CMD*2 ^ mask).upper()[2:] #calculate checksum
last = (CMD*0x10).to_bytes(1, 'big')
pt_new = pt[0:4]+newcnt[2:3]+newcnt[0:1]+newcnt[1:2]+last
pt = pt_new

AUT64 = aut64_encrypt(AUT64_key, pt_new)
KEYstring = "Key1: C0" + str(AUT64[0:7].hex().upper())+"  Key2: " + str(AUT64[7:].hex().upper() + chk_sum) #CHECKSUM: 1D=unlock, 2B=lock
print(KEYstring)
print("AUT64 INPUT: " + pt_new.hex(" ").upper())
print("AUT64 Output: " + AUT64.hex(" ").upper())
#--- increment counter & set unlock end

last   = pt[7]  #changed
print("fob sn:" + serial.hex().upper())
print("counter:" + counter.hex().upper())
print("last:", f"{last:02X}")
new_key ="C0" + str(AUT64[0:8].hex().upper())+chk_sum
print("RAW-KEY: C0" + str(AUT64[0:8].hex().upper())+chk_sum)
