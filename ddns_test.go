package main

import (
	"os"
	"testing"

	//"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/require"
)

func TestDDNS5TokenMaker(t *testing.T) {

	k := ddns5com_Token()
	require.Equal(t, 32, len(k))

	kk := ddns5com_Token()
	require.Equal(t,k,kk)

	_=os.Remove( "/tmp/ddns5.txt")

	kkk:= ddns5com_Token()
	require.Equal(t, 32, len(kkk))

	require.NotEqual(t,k,kkk)

}
