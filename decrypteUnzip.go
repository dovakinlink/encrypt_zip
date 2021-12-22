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
	var privateKeyPath string
	flag.StringVar(&originPath, "o", "", "source path")
	flag.StringVar(&destPath, "d", "", "destination path")
	flag.StringVar(&privateKeyPath, "pem", "", "private key pem file path")
	flag.Parse()

	fi, err := os.Stat(originPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	pkg.DecrypteZip(fi.Size(), privateKeyPath, originPath)
	deCompress(originPath, destPath)
}

func deCompress(originPath string, destPath string) {
	err := pkg.DeCompress(originPath + "_temp", destPath)
	defer os.Remove(originPath + "_temp")
	if err != nil {
		fmt.Println(err)
		return
	}
}
