# ACME Project: Frequently Asked Questions

## How can I get more detailed feedback from the grader in the GitLab CI?

You can obtain more detailed information from the grader by looking at the artifacts (available on the right sight when viewing the output of a CI job). In particular, the file `tester_out.txt` documents precisely which test cases have been passed and which have not (and why).

## I get incomplete points for the `invalid-certificate` test although my implementation seems to behave correctly.

In the `invalid-certificate` test, the certificate of the ACME server, which your client interacts with, is invalid (i.e., not verifiable by means of the root certificate `pebble.minica.pem` provided to you in the code skeleton). Your client should detect this invalid certificate, and should of course not even start an ACME protocol run with an untrusted certificate-issuing server. 

In this test, your DNS server should not be reachable (or at least not respond with the right records) after the invalid certificate has been detected by your client. 
It is desired that your HTTPS server is not reachable, because you cannot start it anyway if you have not obtained a certificate.

## My servers do not seem to receive anything.

This problem can occur in two circumstances: if you use Dockerized Pebble or if you upload your code to the GitLab CI.

The problem is the same in both cases: You probably bound your servers to the `localhost` interface (IP address `127.0.0.1`) instead of the IP provided via the `record` argument (or IP address `0.0.0.0`).
While this configuration works fine for completely local testing, it will not work in the GitLab environment, where requests will be received from different machines, or with Pebble in a Docker container (which counts as 'outside of the machine').

If you are using dockerized Pebble, it's also important to set the `-dnsserver` argument to `10.30.50.1` (your local machine) in the [`docker-compose.yml`](https://github.com/letsencrypt/pebble/blob/main/docker-compose.yml#L5) file (assuming your DNS server in fact runs on your local machine).

## I use `flask` in Python and my HTTP challenge server does not seem to be accessible. Why is that?

In the past few years, we encountered this issue when running the Flask server in a separate process, and could solve it when running the Flask server in a thread of the main process instead.

## I just cannot get my JWS to work correctly.

Some pitfalls to avoid when creating the JWS:

- Don't use the default base64 encoding, but the url-safe base64 encoding with trailing '=' removed (as per [Section 2 of RFC 7515](https://www.rfc-editor.org/rfc/rfc7515#section-2)).
- Remove whitespace and line-breaks in the json dump that should be encoded (ibid).
- Use a proper byte encoding of the integer key parameters (e and n in RSA): The resulting byte string of an integer i should be `ceil( i.bit_length() / 8 )` bytes long. In particular, there must be no leading zero octet in the bytestring ([Section 8 of RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1)).
- When using RSA, create the signature with PKCSv1.5 padding and the SHA256 hash function (as in [Appendix A.2 of RFC7515](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2)) 
- If the request should contain the empty payload `""`, then the request JSON would have to include a base64url encoding of `""` under the `payload` key, not `""`.
- When using elliptic-curve signatures, use the concatenated byte representation of the `r` and `s` values as the signature (the signature output by the cryptographic library is not necessarily in the right format), as stated in [Appendix A.3 of RFC7515](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3).

## My implementation passes the DNS challenges by the ACME server, but not the DNS tests after the protocol run.

When the ACME protocol run finishes, the testing setup tests your DNS server once again. In this test, the `dns.resolver` from `dnspython` is used, which we have learned to be a lot less forgiving than other DNS client implementations (e.g., the one used by Pebble, which accepts your DNS response). The hint to the used library should help you in debugging.

## The scores of my implementation vary from run to run.

 We have made the experience that students who use `socketserver` and `BaseRequestHandler` for the DNS server get unstable results. This issue can be remedied by using `dnslib.DNSServer` instead.

 ## The test setup seems to not find my `run` script.

Confusingly, the problem is not that `/project/run` does not exist (it does), but that the first line of `project/run` reads to a Unix system as `#!/bin/bash^M` instead of `#!/bin/bash` (if the file was edited under Windows). 
It is the interpreter `/bin/bash^M` that does not exist. The `^M` is a carriage return added by DOS. You can fix the format of your `project/run` file as described [here](http://www.nazmulhuda.info/-bin-bash-m-bad-interpreter-no-such-file-or-directory).

## I have trouble installing Pebble.

If you run into the error `installing executables with 'go get' in module mode is deprecated`, the following worked in recent years:

- install go
- setup the gopath (to `/usr/local/go/bin`)
- run `go install github.com/letsencrypt/pebble/...@latest`
- `cd go/bin`
- You now should see the pebble executable. For some reason though go doesn't want to add the config
- manually download the pebble files from the github and add them all to `go/bin`

## My HTTPS server is not reached after the ACME protocol run

The testing script sends a HEAD request to your HTTPS server (the one that should show the downloaded certificate) in order to check whether the HTTPS server is live and reachable. Make sure that your server also responds to HEAD requests.
