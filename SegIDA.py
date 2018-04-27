import idaapi
import idc

class SegIDA:

    def __init__(self,start_addr,num_bytes,filename):
        self.start_addr = start_addr # start address for coredump 49 stack dump $esp 
        self.end_addr = start_addr + int(num_bytes) # set bound for end of segment
        self.createStackSegment(self.start_addr,self.end_addr) # create the segment
        self.buff = readStackFile(filename) # read file in
        self.patchIDB(self.buff)

    def setComment(self,values):
        MakeComm(ScreenEA(), values) # IDA function for setting comment at current line (use jump to move to desired current line)

    def convertRawHexData(self,rawhexdata):
        rawhexdata = rawhexdata.split('x') #seperate raw hex from 0x<value> to [0]0 'x' [1]<value>
        return rawhexdata[1].decode('hex')[::-1] # return decoded hex value, reversed bytes

    def extractStackData(self,rawstackdata):
        jumpaddr,datastr=rawstackdata.split(':') # jumpaddr-<hex_addr> ":" datastr-<hex value> <hex_value> <hex_value> <hex_value>
        jumpaddr = int(jumpaddr,16) # Convert jumpaddr into base16 int
        datastr = datastr.split() #split datastr into a list of four elements: [0] <hex_value> [1] <hex_value> [2] <hex_value> [3] <hex_value>
        return jumpaddr,datastr #return base16 int, four element list

    def readStackFile(self,filename): # read file for processing
        buff=[]
        with open(filename, 'r') as filein:
            buff=filein.readlines()
        return buff

    def createStackSegment(self,start_addr,end_addr):

        idc.AddSeg(start_addr,end_addr,0,1,0, idaapi.saRelDble) #add new segment
        idc.set_segm_combination(start_addr,idaapi.saRelDble) #set segm comb
        idc.jumpto(start_addr) #jumpt to seg start address
        align_start_addr=start_addr #temp align start address value 
        #print "Making DWORDs from 0x%X - 0x%X" % (align_start_addr, end_addr) # debugging statement
        
        while align_start_addr < end_addr: # aligning into 4 byte dw
            MakeDword(align_start_addr) #make the double word alignment
            align_start_addr += 4 #inc address by four bytes
        
        #set segment combination to 'stack'    
        MakeUnknown(align_start_addr, (end_addr-align_start_addr), DOUNK_SIMPLE)
    
    def patchIDB(self,buff):
        for i in buff: # process file contents

            i=i.strip() # strip new line
            jumpaddr,datastr=self.extractStackData(i) # extract jump address and four double words from each line 
            
            for rawbytes in datastr: # process each double word
                
                idc.jumpto(jumpaddr) # jump to segment address 
                temp = self.convertRawHexData(rawbytes)  # process word string into bytes
                idaapi.patch_many_bytes(jumpaddr,temp) # patch bytes at jumpaddr
                self.setComment("Address: 0x%x \tStack Value: %s" % (jumpaddr,rawbytes)) # create a comment at each double word in segment
                jumpaddr +=4 # increment jumpaddr by 4 bytes

# [%] usage: 
x = SegIDA(0xffbb4000,(1148*4),'C:\\Users\\workshopadmin\\Desktop\\vm_share\\dumptxt\\stackdumptxt.log') 