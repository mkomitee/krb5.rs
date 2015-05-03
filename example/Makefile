KRB5_CONFIG=krb5.conf

.PHONY: all clean build test test-aname2lname

all: build

test: test-aname2lname

test-aname2lname: target/debug/aname2lname
	KRB5_CONFIG=$(KRB5_CONFIG) $<

target/debug/aname2lname: build

build:
	cargo build

clean:
	cargo clean
