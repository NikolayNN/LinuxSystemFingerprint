unset GOROOT
unset GOTOOLDIR
export PATH=/usr/local/go/bin:$PATH
hash -r

which go
go version
go env GOROOT GOTOOLDIR
ls /usr/local/go/pkg/tool/linux_amd64/compile

go clean -cache
                      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
                      go build -trimpath -tags netgo,osusergo \
                        -ldflags="-s -w" \
                        -o fingerprint
