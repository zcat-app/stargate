module github.com/zcat-app/stargate/data-plane

go 1.26

toolchain go1.26.3

require (
	github.com/zcat-app/stargate/proto v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.54.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

// The stargate.v1 proto stubs (T009) live in the sibling workspace module
// github.com/zcat-app/stargate/proto — unpublished, so module-mode commands
// (`go mod tidy`) need the relative replace below; workspace builds resolve
// it via go.work either way. Same pattern as tests/contract/go.mod.
replace github.com/zcat-app/stargate/proto => ../proto

require (
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)
