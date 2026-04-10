package broken

// This file intentionally has a type error to trigger packages.Load errors.
var x int = "not an int"
