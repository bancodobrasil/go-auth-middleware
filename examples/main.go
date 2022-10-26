package main

import "os"

func main() {
	arg1 := os.Args[1]

	if arg1 == "gin" {
		RunGinExample()
	}
}
