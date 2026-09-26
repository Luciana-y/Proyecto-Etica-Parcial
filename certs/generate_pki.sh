#!/bin/bash
# Genera una CA propia (interna) y un certificado de servidor firmado por ella
# para habilitar HTTPS/TLS 1.3 en el backend (RS-01).
#
# Nota Windows/Git Bash: MSYS reescribe los argumentos que empiezan con "/"
# (como en -subj "/C=PE/...") tratándolos como rutas. Lo desactivamos para
# que openssl reciba el subject correctamente.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

set -e
cd "$(dirname "$0")"   # ejecutar siempre dentro de la carpeta certs/

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

echo ""
echo "Certificados generados en la carpeta certs/:"
echo "  - ca.crt / ca.key      (CA interna)"
echo "  - server.crt / server.key  (certificado del backend)"
