module example.com/api

go 1.25.4

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/pkg/errors v0.9.2-0.20201214064552-5dd12d0cfe7f // indirect
)

require example.com/shared v0.0.0

replace example.com/shared => ../shared
