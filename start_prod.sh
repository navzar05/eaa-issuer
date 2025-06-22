#!/bin/bash

#Exportam .env
export $(cat .env | xargs)

#Obtinem adresa IP
ip_address_eth=$(ip -4 addr show enp0s31f6 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
ip_address_wireless=$(ip -4 addr show wlp0s20f3 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')


if [ -z "$ip_address_eth" ] && [ -z "$ip_address_wireless" ]; then
    echo "No interface with an IP address set."
    exit 1
elif [ -z "$ip_address_eth" ]; then
    echo "$ip_address_wireless"
    echo "The IP address of wlp0s20f3 is: $ip_address_wireless"
    ip_address=$ip_address_wireless
else
    echo "$ip_address_eth"
    echo "The IP address of enp49s0 is: $ip_address_eth"
    ip_address=$ip_address_eth
fi

files="./CA_certs/san.cnf 
      ./services/authentic-source/keycloak/realms/pid-issuer-realm-realm.json
      ./services/issuer/issuer-server/src/main/resources/application.properties
      ./services/nginx-proxy/nginx_dev.conf
      ./wallet/eudi-app-android-wallet-ui/core-logic/src/demo/java/eu/europa/ec/corelogic/config/ConfigWalletCoreImpl.kt
      ./docker/docker-compose.yaml
      "

for file in $files; do
  if [[ -f $file ]]; then
     sed -i -e "s/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/$ip_address/g" "$file"
    echo "Updated IP address in $file"
  else
    echo "File $file does not exist, skipping..."
  fi
done

ca_key="./config/ca/ca.key"
ca_cert="./config/ca/ca.crt"

declare -A cert_configs=(
    ["./services/issuer/issuer-server/src/main/resources/issuer-server"]="./config/issuer-server-san.cnf"
    ["./services/authentic-source/impl-authz-server-eudi/src/main/resources/authz-server"]="./config/authz-server-san.cnf"
    ["./services/authentic-source/keycloak/certs/keycloak.tls"]="./config/keycloak-san.cnf"
    ["./services/nginx-proxy/certs/nginx"]="./config/nginx-san.cnf"
)

for name in "${!cert_configs[@]}"; do
    config_file="${cert_configs[$name]}"
    echo "Generating certificate for $name using config $config_file"
    
    openssl genpkey -algorithm RSA -out ${name}.key
    openssl req -new -key ${name}.key -out ${name}.csr -config ${config_file}
    openssl x509 -req -in ${name}.csr -CA ${ca_cert} -CAkey ${ca_key} -out ${name}.crt -days 365 -extensions v3_req -extfile ${config_file}
    
    # Clean up CSR file
    rm ${name}.csr
done


openssl pkcs12 -export \
      -inkey ./services/issuer/issuer-server/src/main/resources/issuer-server.key \
      -in ./services/issuer/issuer-server/src/main/resources/issuer-server.crt \
      -out ./services/issuer/issuer-server/src/main/resources/issuer-server.p12 \
      -name issuer-server \
      --passout pass:${ISSUER_SERVER_P12_PASSWORD}

openssl pkcs12 -export \
      -inkey ./services/authentic-source/impl-authz-server-eudi/src/main/resources/authz-server.key \
      -in ./services/authentic-source/impl-authz-server-eudi/src/main/resources/authz-server.crt \
      -out ./services/authentic-source/impl-authz-server-eudi/src/main/resources/authz-server.p12 \
      -name issuer-server \
      --passout pass:${ISSUER_SERVER_P12_PASSWORD}


# keytool -importcert \
#  -trustcacerts \
#  -alias ca-cert \
#  -file ./config/ca/ca.crt \
#  -keystore ./services/issuer/issuer-server/src/main/resources/truststore.p12 \
#  -storepass ${ISSUER_SERVER_TRUSTSTORE_PASSWORD} \
#  -storetype PKCS12 \
#  -noprompt



# keytool -importcert \
#  -trustcacerts \
#  -alias nginx-cert \
#  -file ./services/nginx-proxy/certs/nginx.crt \
#  -keystore ./services/issuer/issuer-server/src/main/resources/truststore.p12 \
#  -storepass ${ISSUER_SERVER_TRUSTSTORE_PASSWORD} \
#  -storetype PKCS12 \
#  -noprompt

#  keytool -importcert \
#  -trustcacerts \
#  -alias nginx-pc-2-cert \
#  -file ./services/nginx-proxy/certs/fullchain.pem \
#  -keystore ./services/issuer/issuer-server/src/main/resources/truststore.p12 \
#  -storepass ${ISSUER_SERVER_TRUSTSTORE_PASSWORD} \
#  -storetype PKCS12 \
#  -noprompt

#   keytool -importcert \
#  -trustcacerts \
#  -alias nginx-pc-3-cert \
#  -file ./services/nginx-proxy/certs/nginx.crt \
#  -keystore ./services/issuer/issuer-server/src/main/resources/truststore.p12 \
#  -storepass ${ISSUER_SERVER_TRUSTSTORE_PASSWORD} \
#  -storetype PKCS12 \
#  -noprompt


# keytool -importcert \
#  -trustcacerts \
#  -alias keycloak-cert \
#  -file ./services/authentic-source/keycloak/certs/keycloak.tls.crt \
#  -keystore ./services/issuer/issuer-server/src/main/resources/truststore.p12 \
#  -storepass ${ISSUER_SERVER_TRUSTSTORE_PASSWORD} \
#  -storetype PKCS12 \
#  -noprompt


# cp ./services/issuer/issuer-server/src/main/resources/issuer-server.crt ./wallet/eudi-app-android-wallet-ui/resources-logic/src/main/res/raw/local_pid_issuer.crt
sudo docker compose -f docker/docker-compose.yaml down
sudo docker compose -f docker/docker-compose.yaml up -d
