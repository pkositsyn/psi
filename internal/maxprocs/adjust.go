package maxprocs

import "runtime"

func Adjust() {
	procs := runtime.GOMAXPROCS(0)

	if procs == 1 {
		return
	}

	if procs < 6 {
		procs--
	} else {
		procs -= 2
	}

	runtime.GOMAXPROCS(procs)
}
