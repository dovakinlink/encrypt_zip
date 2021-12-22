package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

func GeneratePrivateKey() error{
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		fmt.Println(err)
		return err
	}
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type: "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil{
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func LoadPrivateKey(filePath string) (priKey *rsa.PrivateKey, err error) {
	privateKeyFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	privateKey, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		return nil, err
	}
	blockPri, _ := pem.Decode(privateKey)
	prkI, err := x509.ParsePKCS1PrivateKey([]byte(blockPri.Bytes))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return prkI, err
}

func LoadPublicKey(filePath string) (priKey interface{}, err error) {
	publicKeyFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	publicKey, err := ioutil.ReadAll(publicKeyFile)
	if err != nil {
		return nil, err
	}
	blockPub, _ := pem.Decode(publicKey)
	if blockPub == nil {
		return nil, errors.New("blockPub is empty")
	}
	pubKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func EncryptBytes(publicKey *rsa.PublicKey,b []byte) ([]byte, error){
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, b,nil)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

func decrypt(pub *rsa.PublicKey, sig []byte) []byte {
	k := (pub.N.BitLen() + 7) / 8
	m := new(big.Int)
	c := new(big.Int).SetBytes(sig)
	e := big.NewInt(int64(pub.E))
	m.Exp(c, e, pub.N)
	em := leftPad(m.Bytes(), k)
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 1)
	lookingForIndex := 1
	index := 0
	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)
	valid := firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return em[index:]
}
