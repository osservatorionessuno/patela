# Patela

Both client and server for disk-less tor configuration.

Discalimer

I'm not part of [Rust Evangelism Strike
Force](https://enet4.github.io/rust-tropes/rust-evangelism-strike-force/), the
motivation for writing this in rust are:

- Easy to create a single binary application, would be useful for unikernel
- Arti (new tor) is in rust and in future we want to deal with their rpc
  interface squotting the official data structures

## TODO

- caricamento certificati compile time
- quando devo refresharred il contesto del tpm?
- rimuovere i vari expect
- dipendenze interne di alcune trutture dati del protocollo
- spiegare perche' non diamo un overlay, ma conf, piu' sicuro ed e'
  responsabilita' del client
  Test client

## Compile

```console
cargo run -p client
```

Test server

```console
cargo run -p server
```

TPM emulation for dev, install [swtpm](https://github.com/stefanberger/swtpm)

```console
swtpm_setup --tpmstate /tmp/patela/ --create-ek-cert --create-platform-cert --lock-nvram


swtpm_setup --tpm2 --tpmstate ${XDG_CONFIG_HOME}/mytpm1 \
    --create-ek-cert --create-platform-cert --lock-nvram
```

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

```console
/usr/share/swtpm/swtpm-create-user-config-files
mkdir -p ${XDG_CONFIG_HOME}/patela1
swtpm_setup --tpm2 --tpmstate ${XDG_CONFIG_HOME}/patela1
   --create-ek-cert --create-platform-cert --lock-nvram
```
