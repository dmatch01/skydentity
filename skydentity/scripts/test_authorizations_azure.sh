#!/bin/bash
# Example usage: ./test_authorizations_azure.sh -l -r <path to dir containing skydentity repo> -c <path to key file of managed identity w/ firestore access>
# CREDS needs to be the path to a JSON file consisting of two elements, "AZURE_DB_ENDPOINT" and "AZURE_DB_KEY".

ROOT=""
CREDS=""
SKYID_CLIENT_ADDRESS="https://127.0.0.1:5001/"
LOCAL=false

# 0a. Run server and client proxies.
while getopts "r:c:l" option; do
  case $option in
    r)
        ROOT=$OPTARG/skydentity
        ;;
    c)
        CREDS=$OPTARG
        ;;
    l)
        # local client proxy
        LOCAL=true
        ;;
    *)
        echo "Usage: test_authorizations.sh -r <root> -c <credentials> [-l]"
        exit 1
        ;;
  esac
done

if $LOCAL; then
    # local client proxy
    echo "Running local client proxy as HTTP server..."
    echo $ROOT
    pushd $ROOT/azure-client-proxy
    ./run_proxy.sh -s &
    CLIENT_PROCESS=$!
    echo "Client proxy process: $CLIENT_PROCESS"
    popd
    CLIENT_ADDRESS="https://127.0.0.1:5001/"
else
    # serverless client proxy
    pushd $ROOT/serverless-azure-skydentity
    ./deploy_setup.sh
    ./deploy.sh
    CLIENT_ADDRESS=$(gcloud run services list | grep "https://skyidproxy-service")
fi

echo "Client proxy address: $CLIENT_ADDRESS"
pushd $ROOT/azure-server-proxy
SKYID_CLIENT_ADDRESS=$CLIENT_ADDRESS ./run_proxy_https.sh &
SERVER_PROCESS=$!
echo "Server proxy process: $SERVER_PROCESS"
popd

# Wait for the server and client proxies to start
echo "Waiting for the server and client proxies to start..."
sleep 10

# 0b. Upload skydentity/skydentity/policies/config/auth_request_example_azure.yaml 
#    to Firestore using upload_policy.py with the --authorization flag
echo "Uploading auth_request_example_azure.yaml to Firestore..."
python upload_policy.py --policy $ROOT/skydentity/policies/config/auth_request_example_azure.yaml --cloud azure --public-key $ROOT/azure-server-proxy/proxy_util/public_key.pem --credentials $CREDS --authorization

# 1. Run send_auth_request.py. In skydentity/skydentity/policies/config/test_authorization_azure_with_auth.yaml, 
# modify the email address of the managed identity to match the created one.
echo "Sending auth request..."
python send_auth_request.py --resource_yaml_input="$ROOT/skydentity/policies/config/test_authorization_azure.yaml" \
    --resource_yaml_output="$ROOT/skydentity/policies/config/test_authorization_azure_with_auth.yaml"\
    --auth_request_yaml="$ROOT/skydentity/policies/config/auth_request_example_azure.yaml" \
    --capability_enc_key="$ROOT/azure-client-proxy/local_tokens/capability_enc.key" \
    --cloud=azure

# 2. Upload test_authorization_azure_with_auth.yaml to Firestore using upload_policy.py
echo "Uploading test_authorization_azure_with_auth.yaml to Firestore..."
python upload_policy.py --policy $ROOT/skydentity/policies/config/test_authorization_azure_with_auth.yaml --cloud azure --public-key $ROOT/azure-server-proxy/proxy_util/public_key.pem --credentials $CREDS

# 3. Run skydentity/python-server/test_server.py.
echo "Attempting to start VM..."
pushd $ROOT/python-server
python test_server_azure.py
popd

# 4. Check that the managed identity attached to the created VM matches the one from step 2.
ATTACHED=$(az vm identity show --resource-group skydentity --name skydentity-VM1 | jq '.userAssignedIdentities | keys[0]')
EXPECTED=$(grep -F1 "authorization:" $ROOT/skydentity/policies/config/test_authorization_azure_with_auth.yaml | tail -1 | cut -c 7-)
echo "Managed Identity attached to the created VM: $ATTACHED. Expected: $EXPECTED."
echo "Remember to delete the created VM!"

# Cleanup
echo "Cleaning up..."
killall flask

rm $ROOT/skydentity/policies/config/test_authorization_azure_with_auth.yaml