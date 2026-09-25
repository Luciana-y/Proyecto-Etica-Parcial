#!/bin/bash
mkdir -p certs && cd certs

# 1. Generar CA Raíz
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
  -subj "/C=PE/ST=Lima/L=Lima/O=HospitalDS3031/OU=CA_Interna/CN=HospitalRootCA"

# 2. Generar Clave y CSR para el Backend
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=PE/ST=Lima/L=Lima/O=HospitalDS3031/OU=IT/CN=localhost"

# 3. Firmar certificado con la CA Propia
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256