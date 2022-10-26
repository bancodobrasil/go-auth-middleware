package main

import "os"

func main() {
	if len(os.Args) < 2 {
		panic("You must provide a framework name as an argument eg. gin or mux")
	}

	switch os.Args[1] {
	case "gin":
		RunGinExample()
		break
	case "mux":
		RunMuxExample()
		break
	}
}
