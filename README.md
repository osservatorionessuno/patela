# Patela

Both client and server for disk-less tor configuration. Is a pull-based
configuration manager that relies on tpm for identity and crypto operation.

**Patela** is the [piedmont](https://en.wikipedia.org/wiki/Piedmont) word for kick.

> [!WARNING]
> We are not part of [Rust Evangelism Strike
> Force](https://enet4.github.io/rust-tropes/rust-evangelism-strike-force/),
> the motivation for writing this in rust are:
>
> - Easy to create a multi-binary application, would be useful for unikernel
> - Arti (new tor) is in rust and in future we want to deal with their rpc
>   interface squotting the official data structures

## Main components

- [actix-web](https://actix.rs): web server
- [rustls](https://github.com/rustls/rustls): (m)Tls embedded replacement for openssl
- [tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi): tpm2 bindings
- [biscuit](https://www.biscuitsec.org/): session token
- [sqlx](https://github.com/launchbadge/sqlx): simple sql library

## Main flow

### Boot

1. live boot from usb
2. stboot hw validation
3. dhcp mgmt interface
4. fetch linux main stage image from server

### First run

1. `client`: generate rsa keys in the tpm and persist
2. `both`: mtls with the server
3. `server`: authenticate with the public part of the key (in future replace
   with full remote attestation)
4. `server`: generates a bearer token for session
5. `client`: push hw resourcers (ncpu, clock, memory, ...)
6. `server`: generate tor and network configurations
7. `client`: apply configurations
8. `client`: start relays
9. `client`: healthcheck
10. `client`: encrypt tor long term keys with tpm and backup to server

### Second run

1. `client`: read primary key from persistent memory
2. ...
3. ...
4. ...
5. ...
6. `server`: fetch configurations from db
7. ...
8. (bis) `client`: fetch encrypted keys bkp
9. ...

## Future work and design

### Remote attestation

Would be interesting to remote attestate the hardware with a challange resolved
by the tpm. There are many good example, also from the [official
library](https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/examples/certify.rs).
The main idea is that a tpm can **prove** to have a secret and this can be used
to validate the first client enrollment. After the attestation the server can
sign client's certificate with the authority key and go for regular mTLS from
there. The problem is just that is a bit triky to deal with persistent objects
in the tpm, but we'll do!

By now the "workaround" to this limit is to hardcode a client-specific
certificate in the binary already signed by the autority, the certificate can
be stolen but for our thread model is not a big deal because with a valid
certificate you can just ask for new configuration or get the relay keys. If
you try to steal a relay identity the valid relay start to complain and would
be easy to get notified and blacklist the node from the network.

## Getting started

To get tpm and sqlite working is good to configure a couple of variables

```console
export DATABASE_URL="sqlite:$PWD/patela.db"
```

```console
cargo sqlx database setup --source server/migrations
cargo run -p client
```

Test server

```console
cargo run -p server
```

TPM emulation for dev, install [swtpm](https://github.com/stefanberger/swtpm)

To access the tpm device without root permission you should add this udev rule
in `/etc/udev/rules.d/` as show in [reference
docs](https://github.com/tpm2-software/tpm2-tss/blob/master/dist/tpm-udev.rules).

```console
# tpm devices can only be accessed by the tss user but the tss
# group members can access tpmrm devices
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", OWNER="wheel"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="wheel"
KERNEL=="tcm[0-9]*", TAG+="systemd", MODE="0660", OWNER="wheel"
KERNEL=="tcmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="wheel"
```

And reload the rules

```console
udevadm control --reload-rules && udevadm trigger
```

```console
export XDG_CONFIG_HOME=~/.config
```

first setup

```console
/usr/share/swtpm/swtpm-create-user-config-files
mkdir -p ${XDG_CONFIG_HOME}/patela1
swtpm_setup --tpm2 --tpmstate ${XDG_CONFIG_HOME}/patelatpm \
   --create-ek-cert --create-platform-cert --lock-nvram
```

now run the tpm emulator

```console
swtpm socket --tpm2 \
 --server type=tcp,port=2321 \
 --ctrl type=tcp,port=2322 \
 --tpmstate dir=${XDG_CONFIG_HOME}/patelatpm \
 --log file="swtpm.log" \
 --log level=20 \
 --flags not-need-init,startup-clear
```

```console
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
```

## Notes

Here are free words, both for documentation and for future blog post

### Mtls

MTLS is not a complex, you need the autority and the keys, in the server we
have to integrate in actix web, in the client reqwest seems to have a good
support.

- an autority
- client certificate signed by the autority
- server certificate signed by the autority
- client ssl keys are read at compile time

For the server there is good example in the [actix-web
repo](https://github.com/actix/examples/tree/08f3bd3ce45b16aedd52961d6658373922da831b/https-tls/rustls-client-cert).

For the client we have to hardcode the autority and the certificate at compile
time, look into `client/build.rs` if you want the code.

Ok let's start by generating the keys

```console
mkdir certs
openssl req -new -x509 -nodes -days 365 \
   -key certs/cantina-ca-key.pem \
   -out certs/cantina-ca-cert.pem
```

server keys and certs, please note that you have to embed you server name or ip

```console
openssl x509 -req -days 365 -set_serial 01 \
   -in certs/cantina-server-req.pem \
   -out certs/cantina-server-cert.pem \
   -CA certs/cantina-ca-cert.pem \
   -CAkey certs/cantina-ca-key.pem

openssl x509 -req -days 365 -set_serial 01 \
   -in certs/cantina-server-req.pem \
   -out certs/cantina-server-cert.pem \
   -CA certs/cantina-ca-cert.pem \
   -CAkey certs/cantina-ca-key.pem \
   -CAcreateserial -extfile <(printf "subjectAltName=DNS:patela.lol,DNS:localhost,IP:127.0.0.1,IP:::1\n")
```

client keys and certs

```console
openssl req -newkey rsa:4096 -nodes -days 365 \
   -keyout certs/cantina-client-key.pem \
   -out certs/cantina-client-req.pem

openssl x509 -req -days 365000 -set_serial 01 \
   -in certs/cantina-client-req.pem \
   -out certs/cantina-client-cert.pem \
   -CA certs/cantina-ca-cert.pem \
   -CAkey certs/cantina-ca-key.pem
```

verify

```console
openssl verify -CAfile certs/cantina-ca-cert.pem \
   certs/cantina-ca-cert.pem \
   certs/cantina-server-cert.pem

openssl verify -CAfile certs/cantina-ca-cert.pem \
   certs/cantina-ca-cert.pem \
   certs/cantina-client-cert.pem
```

## TPM

Is not trivial to deal with the tpm2 interface, fortunatly the example of the
rust bindings are really well documented, all the patela's code is just a
rework of two example:

1.  [certify](https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/examples/certify.rs)
    for attestation and enrollment with the server
2.  [symmetric file encrypt
    decrypt](https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/examples/symmetric_file_encrypt_decrypt.rs)
    to encrypt the relay's keys for remote backup

## QEMU, Debian and Deploy

For running a qemu/kvm you need some configurations:

- TPM virtualization/passtrought: if you got a permission error on tpm creation
  look the permissions in the `/var/lib/swtpm-localca/`. They should match the
  `swtpm_{user, group}` parameter in `/etc/libvirt/qemu.conf`
- Create a main network a dhcp server exposed: your server should be reachable
  on this network.
- Create a second "isolated" network that will be used for test
- Mount the working directory with `virtiofs` and than `mount -t /{your mount
name} /mnt`

We deploy on a pre-build debian image, but we don't make any assumption, you
just need some deps:

- `systemd`: handling with relay lifecicle
- `dhcp`: a client for the first connection
- `libtss2-dev`: tpm library

If you need to compile for old libc version or other exotic triplet you shuld
checkout [cargo zigbuild](https://github.com/rust-cross/cargo-zigbuild), is
just amazing. In my use case I want to build the debug version on my archlinux
laptop and run in a debian bookworm vm. The two glibc are incompatible but with
zig you need just to run:

`console cargo zigbuild --target x86_64-unknown-linux-gnu.2.36`

To test with qemu/libvirt you can start with a virsh example in
`misc/virsh.xml`, open the file and replace `YOUR_PATH` with a valid
debian/linux kernel image and cpio, there is also a shared filesystem to mount
the code directory inside the guest for dev. This setup assume also a couple of
network interface, one for nat and the other for ip bindings.

Some useful command:

Attach to the console

```console
virsh -c qemu:///system console patela
```

Mount the host filesystem

```console
mount -t virtiofs /patela /mnt
```

Clear tpm from persistent setup

```console
/mnt/target/x86_64-unknown-linux-gnu/debug/patela-client --tpm2 /dev/tpmrm0 tpm clean-persistent
```

Run patela with the server on the host

```console
/mnt/target/x86_64-unknown-linux-gnu/debug/patela-client --server https://192.168.122.1:8020 --tpm2 /dev/tpmrm0
```

If you need to remove all ip address from interface for dev

```console
ip addr flush <DEV>
```
