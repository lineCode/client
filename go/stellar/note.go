package stellar

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/stellar1"
	"golang.org/x/crypto/nacl/secretbox"
)

func noteEncryptB64(ctx context.Context, g *libkb.GlobalContext, note stellar1.NoteContents, other *libkb.User) (noteB64 string, err error) {
	obj, err := noteEncrypt(ctx, g, note, other)
	if err != nil {
		return "", err
	}
	pack, err := libkb.MsgpackEncode(obj)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pack), nil
}

// noteEncrypt encrypts a note for the logged-in user as well as optionally for `other`.
// For a self-note where `other` is nil, uses a secretbox box with a key derived from the logged-in user's PUK.
func noteEncrypt(ctx context.Context, g *libkb.GlobalContext, note stellar1.NoteContents, other *libkb.User) (res stellar1.EncryptedNote, err error) {
	if other != nil {
		return res, fmt.Errorf("TODO: shared note")
	}
	me, err := loadMeUpk(ctx, g)
	if err != nil {
		return res, err
	}
	pukring, err := g.GetPerUserKeyring()
	if err != nil {
		return res, err
	}
	err = pukring.Sync(ctx)
	if err != nil {
		return res, err
	}
	pukGen := pukring.CurrentGeneration()
	pukSeed, err := pukring.GetSeedByGeneration(ctx, pukGen)
	if err != nil {
		return res, err
	}
	symmetricKey, err := pukSeed.DeriveSymmetricKey(libkb.DeriveReasonPUKStellarSelfNote)
	if err != nil {
		return res, err
	}
	res, err = noteEncryptHelper(ctx, note, symmetricKey)
	if err != nil {
		return res, err
	}
	res.Sender = stellar1.NoteRecipient{
		User:   me.ToUserVersion(),
		PukGen: pukGen,
	}
	return res, nil
}

// noteEncryptHelper does the encryption part and returns a partially populated result.
func noteEncryptHelper(ctx context.Context, note stellar1.NoteContents, symmetricKey libkb.NaclSecretBoxKey) (res stellar1.EncryptedNote, err error) {
	// Msgpack
	clearpack, err := libkb.MsgpackEncode(note)
	if err != nil {
		return res, err
	}

	// Secretbox
	var nonce [libkb.NaclDHNonceSize]byte
	nonce, err = libkb.RandomNaclDHNonce()
	if err != nil {
		return res, err
	}
	secbox := secretbox.Seal(nil, clearpack[:], &nonce, (*[libkb.NaclSecretBoxKeySize]byte)(&symmetricKey))

	return stellar1.EncryptedNote{
		V: 1,
		E: secbox,
		N: nonce,
	}, nil
}

func noteDecryptB64(ctx context.Context, g *libkb.GlobalContext, noteB64 string) (res stellar1.NoteContents, err error) {
	pack, err := base64.StdEncoding.DecodeString(noteB64)
	if err != nil {
		return res, err
	}
	var obj stellar1.EncryptedNote
	err = libkb.MsgpackDecode(&obj, pack)
	if err != nil {
		return res, err
	}
	return noteDecrypt(ctx, g, obj)
}

func noteDecrypt(ctx context.Context, g *libkb.GlobalContext, note stellar1.EncryptedNote) (res stellar1.NoteContents, err error) {
	if note.V != 1 {
		return res, fmt.Errorf("unsupported note version: %v", note.V)
	}
	if note.Recipient != nil {
		return res, fmt.Errorf("TODO: shared note")
	}
	me, err := loadMeUpk(ctx, g)
	if err != nil {
		return res, err
	}
	if !note.Sender.User.Eq(me.ToUserVersion()) {
		return res, fmt.Errorf("note not encrypted for logged-in user")
	}
	pukring, err := g.GetPerUserKeyring()
	if err != nil {
		return res, err
	}
	err = pukring.Sync(ctx)
	if err != nil {
		return res, err
	}
	pukSeed, err := pukring.GetSeedByGeneration(ctx, note.Sender.PukGen)
	if err != nil {
		return res, err
	}
	symmetricKey, err := pukSeed.DeriveSymmetricKey(libkb.DeriveReasonPUKStellarSelfNote)
	if err != nil {
		return res, err
	}
	return noteDecryptHelper(ctx, note, symmetricKey)
}

func noteDecryptHelper(ctx context.Context, encNote stellar1.EncryptedNote, symmetricKey libkb.NaclSecretBoxKey) (res stellar1.NoteContents, err error) {
	// Secretbox
	clearpack, ok := secretbox.Open(nil, encNote.E,
		(*[libkb.NaclDHNonceSize]byte)(&encNote.N),
		(*[libkb.NaclSecretBoxKeySize]byte)(&symmetricKey))
	if !ok {
		return res, errors.New("could not decrypt note secretbox")
	}

	// Msgpack
	err = libkb.MsgpackDecode(&res, clearpack)
	return res, err
}
