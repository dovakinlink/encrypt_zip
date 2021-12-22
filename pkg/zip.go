package pkg

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"io"
	"os"
	"strings"
)

func Compress(origin []*os.File, dest string) error {

	zipFile, _ := os.Create(dest)
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	for _, file := range origin{
		err := compress(file, "", writer)
		if err != nil {
			return err
		}
	}
	return nil
}

func compress(file *os.File, prefix string, zw *zip.Writer) error {

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		prefix = prefix + "/" + info.Name()
		fileInofs, err := file.Readdir(-1)
		if err != nil {
			return err
		}
		for _, fi := range fileInofs {
			f, err := os.Open(file.Name() + "/" + fi.Name())
			if err != nil {
				return err
			}
			err = compress(f, prefix, zw)
			if err != nil {
				return err
			}
		}
	} else {
		header, err := zip.FileInfoHeader(info)
		header.Name = prefix + "/" + header.Name
		if err != nil {
			return err
		}
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func DeCompress(zipFile, dest string) error {
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		filename := dest + file.Name
		err = os.MkdirAll(getDir(filename), 0755)
		if err != nil {
			return err
		}
		w, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer w.Close()
		_, err = io.Copy(w, rc)
		if err != nil {
			return err
		}
		w.Close()
		rc.Close()
	}
	return nil
}

func getDir(path string) string {
	return subString(path, 0, strings.LastIndex(path, "/"))
}

func subString(str string, start, end int) string {
	rs := []rune(str)
	length := len(rs)

	if start < 0 || start > length {
		panic("start is wrong")
	}

	if end < start || end > length {
		panic("end is wrong")
	}

	return string(rs[start:end])
}

func EncrypteZip(pgCount int64, publicKeyPath string, zipPath string) {

	bar := pb.Start64(pgCount)

	publicKey, err := LoadPublicKey(publicKeyPath)
	if err != nil {
		return
	}
	pub := publicKey.(*rsa.PublicKey)
	file, err := os.Open(zipPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	var buf [128]byte
	var content []byte
	for {
		n, err := file.Read(buf[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
			return
		}

		if err != nil {
			return
		}
		encryption, err := rsa.EncryptPKCS1v15(rand.Reader, pub, buf[:n])
		bar.Add64(128)
		content  = append(content, encryption...)
	}

	encryptedFile, err := os.Create(zipPath + "_encrypted")
	defer encryptedFile.Close()
	encryptedFile.Write(content)
	bar.Finish()
}

func DecrypteZip(pgCount int64, privateKeyPath string, originPath string) {
	bar := pb.Start64(pgCount)
	privateKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return
	}
	file, err := os.Open(originPath)
	if err != nil {
		return
	}
	defer file.Close()
	var buf [256]byte
	var content []byte
	for {
		n, err := file.Read(buf[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
			return
		}

		if err != nil {
			fmt.Println(err)
			return
		}

		decryption, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, buf[:n])
		bar.Add64(256)
		if err != nil {
			//fmt.Println(err)
		}

		content  = append(content, decryption...)
	}

	decryptedFile, err := os.Create(originPath + "_temp")
	if err != nil {
		fmt.Println(err)
	}
	defer decryptedFile.Close()
	decryptedFile.Write(content)
	bar.Finish()
}