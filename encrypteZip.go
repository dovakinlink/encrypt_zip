package main

import (
	"cryptozip/pkg"
	"flag"
	"fmt"
	"os"
)

func main()  {

	var originPath string
	var destPath string
	var publicKeyPath string
	flag.StringVar(&originPath, "o", "", "source path")
	flag.StringVar(&destPath, "d", "", "destination path")
	flag.StringVar(&publicKeyPath, "pem", "", "public key pem file path")
	flag.Parse()

	if originPath == "" || destPath == "" || publicKeyPath == ""{
		fmt.Println("lack of parameters")
		return
	}

	fi, err := os.Stat(originPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	compress(originPath, destPath)
	pkg.EncrypteZip(fi.Size(), publicKeyPath, destPath)
}

func compress(originPath string, destPath string) {
	f, err := os.Open(originPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	var files = []*os.File{f}
	err = pkg.Compress(files, destPath)
	if err != nil {
		fmt.Println(err)
		return
	}
}


