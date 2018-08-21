package main

import "net"
import "fmt"
import "log"
import "runtime"
import "encoding/binary"

// All parsing is based on https://www.ietf.org/rfc/rfc1035.txt

func main() {
	// listen to incoming udp packets

	addr := net.UDPAddr{
		Port: 53,
		IP:   net.IP{127, 0, 0, 5},
	}
	connection, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	quit := make(chan struct{})

	for i := 0; i < runtime.NumCPU(); i++ {
		go listen(connection, quit)
	}
	<-quit // hang until an error
}

func listen(connection *net.UDPConn, quit chan struct{}) {
        buffer := make([]byte, 1024)
        n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
        for err == nil {
                n, remoteAddr, err = connection.ReadFromUDP(buffer)
				dnsReq := parseDnsRequest(buffer[:n])
				dnsResponse := dnsAnswer {
					dnsReq,
				}
				log.Print("Got request for ", dnsReq.question.name)
				responseBytes := dnsRespons2Bytes(dnsResponse)
				connection.WriteToUDP(responseBytes, remoteAddr)

        }
        fmt.Println("listener failed - ", err)
        quit <- struct{}{}
}

type dnsRequestHeader struct {
	id []byte
	operation int
	auth bool
	truncated bool
	recursion bool
	query_count uint16
}

type dnsQuestion struct {
	name string
	nameBytes []byte
	qtype uint16
	qclass uint16
}

type dnsRequest struct {
	header dnsRequestHeader
	question dnsQuestion
}

type dnsPayload struct {
	name string
}

type dnsAnswer struct {
	request dnsRequest
}



func dnsRespons2Bytes(a dnsAnswer) []byte {
	outBytes := make([]byte, 512)

	header := a.request.header

	outBytes[0] = header.id[0]
	outBytes[1] = header.id[1]

	byte3 := 1 << 7 // Response
	// OPCODE  = 0
	// AUTH = 0
	// TC = 0
	// RD = 0
	outBytes[2] = byte(byte3)

	byte4 :=16
	// RA = 0
	// Z = 001
	// ERR CODE = 0 (No error)
	outBytes[3] = byte(byte4)

	//QDCOUNT = 0
	outBytes[4] = byte(0)
	outBytes[5] = byte(0)

	//ANCOUNT = 1
	outBytes[6] = byte(0)
	outBytes[7] = byte(1)

	//NSCOUNT = 0
	outBytes[8] = byte(0)
	outBytes[9] = byte(0)

	//ARCOUNT = 0
	outBytes[10] = byte(0)
	outBytes[11] = byte(0)

	// Header has a fixed length
	bytesUsed := 12

	q := a.request.question

	outBytes = overwriteAt(q.nameBytes, outBytes, bytesUsed)
	bytesUsed += len(q.nameBytes)
	outBytes[bytesUsed] = byte(0)
	bytesUsed++

	//RR TYPE = 1 (A)
	outBytes[bytesUsed] = byte(0)
	outBytes[bytesUsed + 1] = byte(1)
	bytesUsed += 2

	//CLASS = 1 (IN)
	outBytes[bytesUsed] = byte(0)
	outBytes[bytesUsed + 1] = byte(1)
	bytesUsed += 2

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 100)
	outBytes = overwriteAt(ttl, outBytes, bytesUsed)
	bytesUsed += 4

	outBytes[bytesUsed] = byte(0)
	outBytes[bytesUsed + 1] = byte(4)
	bytesUsed += 2

	ipBytes := []byte{127, 0, 0, 1}
	outBytes = overwriteAt(ipBytes, outBytes, bytesUsed)
	bytesUsed += 4

	return outBytes[:bytesUsed]
}

func overwriteAt(insert []byte, list []byte, start int) []byte {

	for i := 0; i < len(insert); i++ {
		list[start + i] = insert[i]
	}

	return list
}

func parseDnsRequest(request []byte) dnsRequest {

	id := request[:2]
	op := int((request[2] & 120) >> 4) // 120 = 011110000
	auth := int((request[2] & 4) >> 2)// 00000100 = 4
	trunc := int((request[2] & 2) >> 1)// 00000010 = 2
	rec := int(request[2] & 1)// 00000001 = 1
	qCount := binary.BigEndian.Uint16(request[4:6])

	header := dnsRequestHeader {
		id,
		op,
		!(auth == 0),
		!(trunc == 0),
		!(rec == 0),
		qCount,
	}

	q := parseDnsQuestion(request[12:])

	req := dnsRequest {
		header,
		q,
	}

	return req
}

func parseDnsQuestion(q []byte) dnsQuestion {
	labels := make([]byte, 100)
	bytesRead := 0
	offset := 0

	for true {
		cnt := int(q[0+offset])
		bytesUsed := 1

		if cnt == 0 {
			break
		}

		for i := 0; i < cnt; i++ {
			labels[bytesRead] = q[offset + i + 1]
			bytesRead++
			bytesUsed++
		}

		labels[bytesRead] = byte('.')
		bytesRead++

		offset += bytesUsed
	}

	return dnsQuestion{ string(labels), q[:bytesRead], 0, 0 }
}


