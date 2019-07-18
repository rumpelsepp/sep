package sep

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

type TrustDatabase interface {
	AddPeer(fingerprint *Fingerprint) error
	IsTrusted(fingerprint *Fingerprint) bool
}

type Req struct {
	Fingerprint string
}

type Resp struct {
	Ticket string
}

type Delegator struct {
	Trusted  []*Fingerprint
	Listener Listener
}

type server interface {
	accept() (Conn, error)
}

func serve(deleg server) error {
	s := rpc.NewServer()
	s.Register(deleg)

	for {
		conn, err := deleg.accept()
		if err != nil {
			return err
		}

		codec := jsonrpc.NewServerCodec(conn)
		go s.ServeCodec(codec)
	}
}

func (d *Delegator) accept() (Conn, error) {
	return d.Listener.Accept()
}

func (d *Delegator) Serve() error {
	return serve(d)
}

func (d *Delegator) AcquireSessionTicket(req *Req, resp *Resp) error {
	target := req.Fingerprint

	conn, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}

	client := rpc.NewClientWithCodec(jsonrpc.NewClientCodec(conn))

	newReq := &Req{}
	newResp := &Resp{}
	return client.Call("DelegatorTarget.AddPeer", newReq, newResp)
}

func AcquireSessionTicket(conn net.Conn, fingerprint *Fingerprint) error {
	client := rpc.NewClientWithCodec(jsonrpc.NewClientCodec(conn))

	req := &Req{}
	resp := &Resp{}
	return client.Call("Delegator.AcquireSessionTicket", req, resp)
}

type DelegatorTarget struct {
	trusted  []*Fingerprint
	listener Listener
}

func (d *DelegatorTarget) accept() (Conn, error) {
	return d.listener.Accept()
}

func (d *DelegatorTarget) Serve() error {
	return serve(d)
}

func (d *DelegatorTarget) AddPeer(req *Req, resp *Resp) error {
	fmt.Printf("I trust %s now", req.Fingerprint)
	resp.Ticket = "dere"

	return nil
}

func (d *DelegatorTarget) ExpirePeer(req *Req, resp *Resp) error {
	fmt.Printf("I expire %s now", req.Fingerprint)
	resp.Ticket = "dere"

	return nil
}
