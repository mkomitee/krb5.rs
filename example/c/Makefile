LDFLAGS=$(shell krb5-config --libs krb5)
CFLAGS=-Wall -Wextra -Werror
KRB5_CONFIG=../krb5.conf

.PHONY: all clean test test-aname2lname

all: aname2lname

test: test-aname2lname

test-aname2lname: aname2lname
	KRB5_CONFIG=$(KRB5_CONFIG) ./$<

clean:
	rm -f aname2lname
