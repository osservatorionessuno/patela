tpm2_createprimary -C o -G rsa -c primary.ctx
# create RSA
tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx # -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"

# make permanent
tpm2_evictcontrol -C o -c key.ctx 0x81008000
echo "miao miao" > secret.txt

# encrypt secret
tpm2_rsaencrypt -c 0x81008000  -o secret.txt.enc secret.txt
# export the public to send to server
tpm2_readpublic -c 0x81008000 -o key.pem --format=pem

tpm2_flushcontext -t
tpm2_flushcontext -l
tpm2_flushcontext -s

# can decrypt with the handle
tpm2_rsadecrypt -c 0x81008000 secret.txt.enc

# or reload the key
tpm2_createprimary -C o -c primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_rsadecrypt -c key.ctx secret.txt.enc

# --------------------------------------------------------

tpm2_createprimary -C o -G rsa -c primary.ctx
# create AES
tpm2_create -C primary.ctx -G aes -g sha256 -u symkey.pub -r symkey.priv -c symkey.ctx # -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"

# make permanent
tpm2_evictcontrol -C o -c symkey.ctx 0x81010001
echo "miao miao" > secret.txt

head -c 16 /dev/urandom > iv.bin

# encrypt with AES
tpm2_encryptdecrypt -Q --iv iv.bin -c 0x81010001 -o secret.txt.enc secret.txt

tpm2_flushcontext -t
tpm2_flushcontext -l
tpm2_flushcontext -s

# decrypt with AES
tpm2_encryptdecrypt -Q --iv iv.bin -c 0x81010001 -d -o decrypt.out secret.txt.enc