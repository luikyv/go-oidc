package main

func main() {
	err := RunFAPI2OpenIDProvider()
	if err != nil {
		panic(err.Error())
	}
}
