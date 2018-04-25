
#alignment variables:
#https://www.hex-rays.com/products/ida/support/sdkdoc/group__sa__.html

#align to four byte in segment
#https://reverseengineering.stackexchange.com/questions/1973/how-to-change-a-large-section-of-bytes-to-words-in-ida-pro

#create segment
#https://gist.github.com/williballenthin/8bfa8e25f36e6f619247203d1bc0291b

import idautils
import idaapi
import idc

def setComment(values):
    MakeComm(ScreenEA(), values)
sc = idautils.Strings()


#print len(sc)
print type(sc)
for s in sc:
    #print "%x: len=%d type=%s -> '%s'" % (s.ea, s.length, type(s), str(s))
    if 'Setup' in str(s):
        print str(s)
    if 'sound' in str(s):
        print str(s)
    if 'Sound' in str(s):
        print str(s)
start_addr = 0xffbb4000
value = 1148*4
end_addr =0xffbb4000 + int(value)
idc.AddSeg(start_addr,end_addr,0,1,0, idaapi.saRelDble)
idc.set_segm_combination(start_addr,idaapi.saRelDble)
#idc.set_segm_combination(startea, comb possibly sc)
idc.jumpto(start_addr)
#idc.jumpto(start_addr + 0x4)
align_start_addr=start_addr
align_end_addr=end_addr
print "Making DWORDs from 0x%X - 0x%X" % (align_start_addr, align_end_addr)

MakeUnknown(align_start_addr, (align_end_addr-align_start_addr), DOUNK_SIMPLE)

while align_start_addr < align_end_addr:
    MakeDword(align_start_addr)
    align_start_addr += 4

for i in range(start_addr,end_addr,4):
    idc.jumpto(i)
    #idc.set_manual_insn(i,str(i))
    setComment("Dummy value: %x" %i)
    #print "after update: %x"%i
end = (end_addr-start_addr)
addr = start_addr

for i in range(0,end,4):
    temp =str(i)
    hex_data = temp.encode("hex")
    print temp
    idc.jumpto(addr)

    idaapi.patch_many_bytes(addr,hex_data)
    addr+=4

