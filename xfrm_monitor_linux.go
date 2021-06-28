package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type XfrmMsg interface {
	Type() nl.XfrmMsgType
}

type XfrmMsgExpire struct {
	XfrmState *XfrmState
	Hard      bool
}

func (ue *XfrmMsgExpire) Type() nl.XfrmMsgType {
	return nl.XFRM_MSG_EXPIRE
}

func parseXfrmMsgExpire(b []byte) *XfrmMsgExpire {
	var e XfrmMsgExpire

	msg := nl.DeserializeXfrmUserExpire(b)
	e.XfrmState = xfrmStateFromXfrmUsersaInfo(&msg.XfrmUsersaInfo)
	e.Hard = msg.Hard == 1

	return &e
}

//
type XfrmMsgSa struct {
	nl.XfrmUsersaInfo
	XfrmState *XfrmState
	saType    nl.XfrmMsgType
}

func (sa *XfrmMsgSa) Type() nl.XfrmMsgType {
	return sa.saType
}

func parseXfrmMsgSa(b []byte, t nl.XfrmMsgType) *XfrmMsgSa {
	var msg = nl.XfrmUsersaInfo{}
	binary.Read(bytes.NewReader(b[0:nl.SizeofXfrmUsersaInfo]), nl.NativeEndian(), &msg)

	var stat *XfrmState
	stat, _ = parseXfrmState(b, FAMILY_ALL)

	return &XfrmMsgSa{
		XfrmUsersaInfo: msg,
		XfrmState:      stat,
		saType:         t,
	}
}

//
type XfrmUserSaId struct {
	SaId   *nl.XfrmUsersaId
	saType nl.XfrmMsgType
}

func (saId *XfrmUserSaId) Type() nl.XfrmMsgType {
	return saId.saType
}

func parseXfrmMsgSaId(b []byte, t nl.XfrmMsgType) *XfrmUserSaId {
	saId := nl.DeserializeXfrmUsersaId(b)

	return &XfrmUserSaId{
		SaId:   saId,
		saType: t,
	}
}

//
type XfrmPolicy__ struct {
	Policy *XfrmPolicy
	t      nl.XfrmMsgType
}

func (p *XfrmPolicy__) Type() nl.XfrmMsgType {
	return p.t
}

//
type XfrmUserpolicyId__ struct {
	Id *nl.XfrmUserpolicyId
	t  nl.XfrmMsgType
}

func (id *XfrmUserpolicyId__) Type() nl.XfrmMsgType {
	return id.t
}
func parseXfrmUserpolicyId(b []byte, t nl.XfrmMsgType) *XfrmUserpolicyId__ {
	return &XfrmUserpolicyId__{
		Id: nl.DeserializeXfrmUserpolicyId(b),
		t:  t,
	}
}

func XfrmMonitor(ch chan<- XfrmMsg, done <-chan struct{}, errorChan chan<- error,
	types ...nl.XfrmMsgType) error {

	groups, err := xfrmMcastGroups(types)
	if err != nil {
		return nil
	}
	s, err := nl.SubscribeAt(netns.None(), netns.None(), unix.NETLINK_XFRM, groups...)
	if err != nil {
		return err
	}

	if done != nil {
		go func() {
			<-done
			s.Close()
		}()

	}

	go func() {
		defer close(ch)
		for {
			msgs, from, err := s.Receive()
			if err != nil {
				errorChan <- err
				return
			}
			if from.Pid != nl.PidKernel {
				errorChan <- fmt.Errorf("Wrong sender portid %d, expected %d", from.Pid, nl.PidKernel)
				return
			}
			for _, m := range msgs {
				//fmt.Printf("msg type: %x\n", m.Header.Type)

				switch m.Header.Type {
				case nl.XFRM_MSG_EXPIRE:
					ch <- parseXfrmMsgExpire(m.Data)
				case nl.XFRM_MSG_NEWSA, nl.XFRM_MSG_UPDSA:
					ch <- parseXfrmMsgSa(m.Data, nl.XfrmMsgType(m.Header.Type))
				case nl.XFRM_MSG_DELSA:
					ch <- parseXfrmMsgSaId(m.Data, nl.XfrmMsgType(m.Header.Type))
				case nl.XFRM_MSG_NEWPOLICY, nl.XFRM_MSG_UPDPOLICY:
					policy, err := parseXfrmPolicy(m.Data, FAMILY_ALL)
					if err != nil {
						errorChan <- err
					} else {
						ch <- &XfrmPolicy__{
							Policy: policy,
							t:      nl.XfrmMsgType(m.Header.Type),
						}
					}
				case nl.XFRM_MSG_DELPOLICY:
					ch <- parseXfrmUserpolicyId(m.Data, nl.XfrmMsgType(m.Header.Type))
				default:
					errorChan <- fmt.Errorf("unsupported msg type: %x", m.Header.Type)
				}
			}
		}
	}()

	return nil
}

func xfrmMcastGroups(types []nl.XfrmMsgType) ([]uint, error) {
	groups := make([]uint, 0)

	if len(types) == 0 {
		return nil, fmt.Errorf("no xfrm msg type specified")
	}

	for _, t := range types {
		var group uint

		switch t {
		case nl.XFRM_MSG_EXPIRE:
			group = nl.XFRMNLGRP_EXPIRE
		case nl.XFRM_MSG_NEWSA, nl.XFRM_MSG_DELSA, nl.XFRM_MSG_UPDSA:
			group = nl.XFRMNLGRP_SA
		case nl.XFRM_MSG_NEWPOLICY, nl.XFRM_MSG_DELPOLICY, nl.XFRM_MSG_UPDPOLICY:
			group = nl.XFRMNLGRP_POLICY
		default:
			return nil, fmt.Errorf("unsupported group: %x", t)
		}

		groups = append(groups, group)
	}

	return groups, nil
}
