# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255  # Time to live

        # A variable I created for part 4
        __packetLost = 0    # This is to count the number of packets lost during a ping

        __DEBUG_IcmpPacket = False  # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # This is a getter I created for part 4
        def getPacketLost(self):
            return self.__packetLost

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # This is a setter I created for part 4
        def incrementPacketLost(self):
            self.__packetLost = self.__packetLost + 1

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        # DONE - TODO: This function for part 1 and 2
        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            # icmpReplyPacket.setIsValidResponse(True)
            # pass

            # 1. Confirm the following items received are the same as what was sent: sequence number, packet identifier, raw data
            isValid = False
            # It's a long line so that there don't have to be multiple if statements or impeded if statements (Used pycharm recommendation, made it easier to read)
            if icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber() \
                    and icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier() \
                    and icmpReplyPacket.getIcmpData() == self.getDataRaw():
                isValid = True

            # This is for part 2 of the project, using our setters so we can compare later
            if icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber():
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
                icmpReplyPacket.setReceivedSequence(self.getPacketSequenceNumber())

            if icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier():
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
                icmpReplyPacket.setReceivedIdentifier(self.getPacketIdentifier())

            if icmpReplyPacket.getIcmpData() == self.getDataRaw():
                icmpReplyPacket.setIcmpRawData_isValid(True)
                icmpReplyPacket.setReceivedDataRaw(self.getDataRaw())

            # 2. Set the valid data variable in the IcmpPacket_EchoReply class based the outcome of the data comparison.
            # if true do thing
            if isValid:
                icmpReplyPacket.setIsValidResponse(True)

            # 3. Create variables within the IcmpPacket_EchoReply class that identify whether each value that can be obtained
            #       from the class is valid. For example, the IcmpPacket_EchoReply class has an IcmpIdentifier. Create a variable,
            #       such as IcmpIdentifier_isValid, along with a getter function, such as getIcmpIdentifier_isValid(), and setting
            #       function, such as setIcmpIdentifier_isValid(), so you can easily track and identify which data points within
            #       the echo reply are valid. Note: There are similar examples within the current skeleton code.
            # Done below in the IcmpEcho class In the variables section, getter section, and setter section

            # 4. Create debug messages that show the expected and the actual values along with the result of the comparison.
            if self.__DEBUG_IcmpPacket:
                print("The following is (expected values) :: (actual values)")
                print(icmpReplyPacket.getIcmpSequenceNumber(), " :: ", self.getPacketSequenceNumber())
                print(icmpReplyPacket.getIcmpIdentifier(), " :: ", self.getPacketIdentifier())
                print(icmpReplyPacket.getIcmpData(), " :: ", self.getDataRaw())
                print("Was the above valid: ", isValid, "\n")

        # Creating functions for part 4
        @staticmethod
        def __codeMessage(IcmpType, code):
            returnMessage = ""
            if IcmpType == 3:
                if code == 0:
                    returnMessage = "Net Unreachable"
                elif code == 1:
                    returnMessage = "Host Unreachable"
                elif code == 2:
                    returnMessage = "Protocol Unreachable"
                elif code == 3:
                    returnMessage = "Port Unreachable"
                elif code == 4:
                    returnMessage = "Fragmentation Needed and Don't Fragment was Set"
                elif code == 5:
                    returnMessage = "Source Route Failed"
                elif code == 6:
                    returnMessage = "Destination Network Unknown"
                elif code == 7:
                    returnMessage = "Destination Host Unknown"
                elif code == 8:
                    returnMessage = "Source Host Isolated"
                elif code == 9:
                    returnMessage = "Communication with Destination Network is Administratively Prohibited"
                elif code == 10:
                    returnMessage = "Communication with Destination Host is Administratively Prohibited	"
                elif code == 11:
                    returnMessage = "Destination Network Unreachable for Type of Service	"
                elif code == 12:
                    returnMessage = "Destination Host Unreachable for Type of Service	"
                elif code == 13:
                    returnMessage = "Communication Administratively Prohibited	"
                elif code == 14:
                    returnMessage = "Host Precedence Violation	"
                elif code == 15:
                    returnMessage = "Precedence cutoff in effect	"

                return returnMessage

            if IcmpType == 11:
                if code == 0:
                    returnMessage = "Time to Live exceeded in Transit"
                elif code == 1:
                    returnMessage = "Fragment Reassembly Time Exceeded"

                return returnMessage

            if IcmpType == 12:
                if code == 0:
                    returnMessage = "Pointer indicates the error"
                elif code == 1:
                    returnMessage = "Missing a Required Option"
                elif code == 2:
                    returnMessage = "Bad Length"

                return returnMessage

            return "The code wasn't found"

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        # TODO: This function for part 4
        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    self.incrementPacketLost()  # Added for part 4
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    self.incrementPacketLost()  # Added for part 4
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        self.incrementPacketLost()  # Added for part 4
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )
                        print(self.__codeMessage(11, icmpCode))

                    elif icmpType == 3:                         # Destination Unreachable
                        self.incrementPacketLost()  # Added for part 4
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        print(self.__codeMessage(3, icmpCode))

                    elif icmpType == 12:                         # Parameter Problem
                        self.incrementPacketLost()  # Added for part 4
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        print(self.__codeMessage(12, icmpCode))

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                self.incrementPacketLost()  # Added for part 4
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        # TODO: This function for part 5
        def sendTracerouteRequest(self):
            # Return values maybe
            localTimer = 0
            localAddr = "0.0.0.0"

            # Create the socket information
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(2)   # Changed value from self.__ipTimeout to 2 #TODO: Change this to something
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes

            try:
                # Lots of time information
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 2    # changed from 30 to 2 #TODO: Change this to something
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)

                if whatReady[0] == []:  # Timeout
                    print("  *        *        *       Request timed out.")
                    pass    # Continue with the rest of the program?

                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                localAddr = addr[0]    # Added so the return would accept it (Part 5)

                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                localTimer = (timeReceived - pingStartTime) * 1000  # Added so the return would accept it (Part 5)

                if timeLeft <= 0:
                    print("  *        *        *       Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )
                        print(self.__codeMessage(11, icmpCode))

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        print(self.__codeMessage(3, icmpCode))

                    elif icmpType == 12:                         # Parameter Problem
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        print(self.__codeMessage(12, icmpCode))

                    elif icmpType == 0:                         # Echo Reply
                        # icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        # self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        # icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return localTimer, localAddr    # If I get a machine I just need to return the values

                    else:
                        print("error")
            except timeout:
                # TODO: Do something in here maybe?
                # print("  *        *        *        Request timed out (By Exception).")
                pass
            finally:
                mySocket.close()

            return localTimer, localAddr

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # Stuff for part 3 of __validateIcmpReplyPacketWithOriginalPingData
        IcmpRawData_isValid = False
        IcmpIdentifier_isValid = False
        IcmpSequenceNumber_isValid = False

        # Stuff for part 2 (printResultToConsole)
        __receivedPacketIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __receivedPacketSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __receivedDataRaw = ""  # Raw string data before encoding

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # Stuff for part 3 of __validateIcmpReplyPacketWithOriginalPingData
        def getIcmpRawData_isValid(self):
            return self.IcmpRawData_isValid

        def getIcmpIdentifier_isValid(self):
            return self.IcmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.IcmpSequenceNumber_isValid

        # Stuff for part 2 (printResultToConsole)
        def getReceivedIdentifier(self):
            return self.__receivedPacketIdentifier

        def getReceivedSequence(self):
            return self.__receivedPacketSequenceNumber

        def getReceivedDataRaw(self):
            return self.__receivedDataRaw

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # Stuff for part 3 of __validateIcmpReplyPacketWithOriginalPingData
        def setIcmpRawData_isValid(self, booleanValue):
            self.IcmpRawData_isValid = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.IcmpIdentifier_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.IcmpSequenceNumber_isValid = booleanValue

        # Stuff for part 2 (printResultToConsole)
        def setReceivedIdentifier(self, packetIdentifier):
            self.__receivedPacketIdentifier = packetIdentifier

        def setReceivedSequence(self, sequenceNumber):
            self.__receivedPacketSequenceNumber = sequenceNumber

        def setReceivedDataRaw(self, rawData):
            self.__receivedDataRaw = rawData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        # DONE - TODO: This function for part 2
        def printResultToConsole(self, ttl, timeReceived, addr):
            if self.getIcmpIdentifier_isValid() is False:
                print("Identifier Error: Expecting %d but received %d",
                      (self.getIcmpIdentifier(), self.getReceivedIdentifier()))
            if self.getIcmpSequenceNumber_isValid() is False:
                print("Sequence Number Error: Expecting %d but received %d",
                      (self.getIcmpSequenceNumber(), self.getReceivedSequence()))
            if self.getIcmpRawData_isValid() is False:
                print("Raw Data Error: Expecting %d but received %d", (self.getIcmpData(), self.getReceivedDataRaw()))

            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    # DONE - TODO: This function for part 3
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # An array for all Rtt values gathered in the following loop (Part 3)
        rttValues = []

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            pingStartTime = time.time()  # I added this for part 3, timer start
            icmpPacket.sendEchoRequest()  # Build IP
            timeReceived = time.time()  # I added this for part 3, timer end

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

            # Stuff for part 3 that I added below
            rttValues.append((timeReceived - pingStartTime) * 1000)  # push the timer into the array

        # All the stuff below is needed for part 3 to display the rtt information
            # Apparently the first value may be much higher and not match my Rtt because it is hitting the first router (according to TA)
        length = len(rttValues)
        minRtt = rttValues[0]
        maxRtt = rttValues[0]
        for i in range(length):
            if rttValues[i] > maxRtt:
                maxRtt = rttValues[i]
            if rttValues[i] < minRtt:
                minRtt = rttValues[i]
        average = sum(rttValues)/length
        # This is my attempt to mimic what cmd ping does
        # print("\nMy RTT Values: ", rttValues)

        lostPackets = icmpPacket.getPacketLost()
        percentLoss = (1.0 - ((4 - lostPackets) / 4)) * 100
        print("\nPing statistics for %s:" % host)
        print("\tPackets: Sent = %d, Received = %d, Lost = %d (%d%% loss)," % (4, 4 - lostPackets, lostPackets, percentLoss))

        print("Approximate round trip times in milli-seconds:")
        print("\tMinimum = %dms, Maximum = %dms, Average = %dms" % (minRtt, maxRtt, average))

    # TODO: This function for part 5
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

        # May need to use checkSum and IcmpPacket
        print("traceroute to %s [%s]\nover a maximum of 30 hops:\n" % (host, gethostbyname(host)))
        ttlCounter = 1  # Could just use i but decided to be more explicit with it
        totalTimeTaken = 0

        # Max hops are 30, hence the range to 30
        for i in range(1, 30):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            icmpPacket.setTtl(ttlCounter)

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            # Make my timer how long it takes to run the program
            startTime = time.time()
            timeReturned, addr = icmpPacket.sendTracerouteRequest()  # Build IP
            endTime = time.time()
            totalTimeTaken += (endTime - startTime) * 1000

            # Don't need it to print out when I just got the default stuff
            if addr != "0.0.0.0":
                print(" %d\trtt=%dms\t\t%s" % (i, totalTimeTaken, addr))

            # If address reached, then we are done
            if gethostbyname(host) == addr:
                 break
            ttlCounter += 1

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("oregonstate.edu")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    icmpHelperPing.traceRoute("oregonstate.edu")
    # icmpHelperPing.traceRoute("google.com")
    # icmpHelperPing.traceRoute("www.sweden.se")
    # icmpHelperPing.traceRoute("101.0.86.43")


if __name__ == "__main__":
    main()
