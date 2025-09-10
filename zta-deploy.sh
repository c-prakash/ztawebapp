#!/bin/bash

# Azure Zero Trust Network for Web Applications - Infrastructure Deployment Script
# Based on: https://learn.microsoft.com/en-us/azure/networking/create-zero-trust-network-web-apps
# 
# This script creates a complete Zero Trust architecture with:
# - Hub/Spoke VNet topology with peering
# - Application Gateway with WAF v2
# - Azure Firewall Premium with TLS inspection
# - App Service with private endpoints
# - Key Vault for certificate management
# - Custom DNS zones and routing tables
# - Network security groups for additional protection

set -e  # Exit on any error
#set -x

# =============================================================================
# CONFIGURATION VARIABLES - MODIFY THESE FOR YOUR ENVIRONMENT
# =============================================================================

# Basic settings
RESOURCE_GROUP="zta-rg"
LOCATION="East US"
SUBSCRIPTION_ID="[Subscription ID]"  # Leave empty to use default subscription

# Domain and certificate settings - CRITICAL: You MUST have these ready
DOMAIN_NAME="[Public Domain Name]"  # Replace with your actual domain
CERT_FILE_PATH="[Cert file path - PFX Only]"  # Path to your wildcard certificate
CERT_PASSWORD="[Cert Password]"  # Certificate password

# Resource naming (you can customize these)
KEY_VAULT_NAME="drcpZTAKeyVault-1"  # Appending timestamp for uniqueness
MANAGED_IDENTITY_NAME="ztaManagedIDappGW"
WEB_APP_NAME="drcprakashZTAWebApp"  # Must be globally unique
APP_SERVICE_PLAN="ztaASP"
DNS_ZONE_NAME="$DOMAIN_NAME"

# Network configuration
HUB_VNET_NAME="hub-vnet"
HUB_VNET_CIDR="192.168.0.0/16"
FIREWALL_SUBNET_CIDR="192.168.100.0/24"

SPOKE_VNET_NAME="spoke-vnet"
SPOKE_VNET_CIDR="172.16.0.0/16"
APPGW_SUBNET_CIDR="172.16.0.0/24"
APP_SUBNET_CIDR="172.16.1.0/24"

# Azure services naming
APP_GATEWAY_NAME="ztaAppGateway"
FIREWALL_NAME="mztaFirewall"
WAF_POLICY_NAME="ztaWAFpolicy"
FIREWALL_POLICY_NAME="ztaFirewallPolicy"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Azure CLI is installed
    if ! command -v az &> /dev/null; then
        echo "ERROR: Azure CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if logged in
    if ! az account show &> /dev/null; then
        echo "ERROR: Not logged into Azure. Run 'az login' first."
        exit 1
    fi
    
    # Check certificate file exists
    if [[ ! -f "$CERT_FILE_PATH" ]]; then
        echo "ERROR: Certificate file not found at: $CERT_FILE_PATH"
        echo "Please update CERT_FILE_PATH with the correct path to your wildcard certificate."
        exit 1
    fi
    
    # Validate domain name format
    if [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        echo "ERROR: Invalid domain name format: $DOMAIN_NAME"
        exit 1
    fi
    
    log "Prerequisites check passed ✓"
}

wait_for_deployment() {
    local resource_type="$1"
    local resource_name="$2"
    log "Waiting for $resource_type '$resource_name' deployment to complete..."
    sleep 10  # Basic wait - Azure CLI commands are generally synchronous
}

# =============================================================================
# MAIN DEPLOYMENT FUNCTIONS
# =============================================================================

setup_subscription() {
    log "Setting up Azure subscription context..."
    
    if [[ -n "$SUBSCRIPTION_ID" ]]; then
        az account set --subscription "$SUBSCRIPTION_ID"
        log "Using subscription: $SUBSCRIPTION_ID"
    else
        local current_sub=$(az account show --query id -o tsv)
        log "Using current subscription: $current_sub"
    fi
}

create_resource_group() {
    log "Creating resource group: $RESOURCE_GROUP"
    
    az group create \
        --name "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output table
    
    log "Resource group created ✓"
}

create_key_vault() {
    log "Creating Key Vault: $KEY_VAULT_NAME"
    
    # Create Key Vault with 7-day retention for easy cleanup
    az keyvault create \
        --name "$KEY_VAULT_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku standard \
        --retention-days 7 \
        --enable-purge-protection true \
        --output table
    
    log "Key Vault created ✓"
    
    # Upload certificate to Key Vault
    log "Uploading certificate to Key Vault..."
    
    az keyvault certificate import \
        --vault-name "$KEY_VAULT_NAME" \
        --name "ztaTrustedWildCard" \
        --file "$CERT_FILE_PATH" \
        --password "$CERT_PASSWORD" \
        --output table
    
    log "Certificate uploaded to Key Vault ✓"
}

create_managed_identity() {
    log "Creating managed identity: $MANAGED_IDENTITY_NAME"
    
    # Create user-assigned managed identity
    az identity create \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output table
    
    # Get the identity's principal ID for Key Vault access
    local identity_principal_id=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query principalId -o tsv)
    
    log "Managed identity created with Principal ID: $identity_principal_id ✓"
    
    # Grant Key Vault access to managed identity
    log "Granting Key Vault access to managed identity..."
    
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --object-id "$identity_principal_id" \
        --secret-permissions get \
        --certificate-permissions get \
        --output table
    
    log "Key Vault access granted ✓"
}

create_virtual_networks() {
    log "Creating hub virtual network: $HUB_VNET_NAME"
    
    # Create hub VNet with firewall subnet
    az network vnet create \
        --name "$HUB_VNET_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --address-prefix "$HUB_VNET_CIDR" \
        --subnet-name "AzureFirewallSubnet" \
        --subnet-prefix "$FIREWALL_SUBNET_CIDR" \
        --output table
    
    log "Hub VNet created ✓"
    
    log "Creating spoke virtual network: $SPOKE_VNET_NAME"
    
    # Create spoke VNet with Application Gateway subnet
    az network vnet create \
        --name "$SPOKE_VNET_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --address-prefix "$SPOKE_VNET_CIDR" \
        --subnet-name "AppGwSubnet" \
        --subnet-prefix "$APPGW_SUBNET_CIDR" \
        --output table
    
    # Add App Service subnet to spoke VNet
    az network vnet subnet create \
        --name "App1" \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$SPOKE_VNET_NAME" \
        --address-prefix "$APP_SUBNET_CIDR" \
        --output table
    
    log "Spoke VNet created with subnets ✓"
    
    # Create VNet peering between hub and spoke
    log "Creating VNet peering..."
    
    # Hub to Spoke peering
    az network vnet peering create \
        --name "hub-to-spoke" \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$HUB_VNET_NAME" \
        --remote-vnet "$SPOKE_VNET_NAME" \
        --allow-vnet-access true \
        --allow-forwarded-traffic true \
        --output table
    
    # Spoke to Hub peering
    az network vnet peering create \
        --name "spoke-to-hub" \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$SPOKE_VNET_NAME" \
        --remote-vnet "$HUB_VNET_NAME" \
        --allow-vnet-access true \
        --allow-forwarded-traffic true \
        --output table
    
    log "VNet peering established ✓"
}

create_dns_zone() {
    log "Creating DNS zone: $DNS_ZONE_NAME"
    
    az network dns zone create \
        --name "$DNS_ZONE_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --output table
    
    # Display name servers for manual configuration
    log "DNS zone created ✓"
    log "IMPORTANT: Update your domain's name servers to:"
    az network dns zone show \
        --name "$DNS_ZONE_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query nameServers \
        --output table
}

create_app_service() {
    log "Creating App Service Plan: $APP_SERVICE_PLAN"
    
    # Create App Service Plan
    az appservice plan create \
        --name "$APP_SERVICE_PLAN" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku S1 \
        --output table
    
    log "Creating App Service: $WEB_APP_NAME"
    
    # Create App Service
    az webapp create \
        --name "$WEB_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --plan "$APP_SERVICE_PLAN" \
        --runtime "dotnet:8" \
        --output table
    
    log "App Service created ✓"
    
    # Create private endpoint for App Service
    log "Creating private endpoint for App Service..."
    
    # First, disable public network access
    az webapp update \
        --name "$WEB_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --set publicNetworkAccess=Disabled
    
    # Create private endpoint
    az network private-endpoint create \
        --name "pe-appservice" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --vnet-name "$SPOKE_VNET_NAME" \
        --subnet "App1" \
        --private-connection-resource-id "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$WEB_APP_NAME" \
        --group-id sites \
        --connection-name "pe-appservice-connection" \
        --output table
    
    log "Private endpoint created for App Service ✓"
}

create_application_gateway() {
    log "Creating Application Gateway public IP..."


    # Create public IP for Application Gateway
    az network public-ip create \
        --name "ztaAppGWpip" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --allocation-method Static \
        --sku Standard \
        --output table
    
    log "Creating WAF Policy: $WAF_POLICY_NAME"
    
    # Create WAF Policy
    az network application-gateway waf-policy create \
        --name "$WAF_POLICY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output table
    
    log "Creating Application Gateway: $APP_GATEWAY_NAME"
    
    # Get managed identity resource ID
    local identity_id=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query id -o tsv)
    
    # Create Application Gateway with initial HTTP defaults
    az network application-gateway create \
        --name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --capacity 1 \
        --sku WAF_v2 \
        --vnet-name "$SPOKE_VNET_NAME" \
        --subnet "AppGwSubnet" \
        --public-ip-address "ztaAppGWpip" \
        --http-settings-cookie-based-affinity Disabled \
        --http-settings-port 80 \
        --http-settings-protocol Http \
        --frontend-port 80 \
        --waf-policy "$WAF_POLICY_NAME" \
        --identity "$identity_id" \
        --priority 200 \
        --output table
    
    wait_for_deployment "Application Gateway" "$APP_GATEWAY_NAME"
    
    log "Adding SSL certificate from Key Vault to Application Gateway..."
    
    # Add Key Vault certificate to Application Gateway
    az network application-gateway ssl-cert create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaTrustedWildCard" \
        --key-vault-secret-id "https://$KEY_VAULT_NAME.vault.azure.net/secrets/ztaTrustedWildCard" \
        --output table
    
    # Verify SSL certificate
    log "Verifying SSL certificate..."
    if ! az network application-gateway ssl-cert show \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaTrustedWildCard" \
        --output table; then
        log "ERROR: SSL certificate creation failed. Check Key Vault secret and permissions."
        exit 1
    fi
    
    # Add HTTPS frontend port
    log "Creating HTTPS frontend port..."
    az network application-gateway frontend-port create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "httpsPort" \
        --port 443 \
        --output table
    
    # Verify frontend port
    log "Verifying HTTPS frontend port..."
    if ! az network application-gateway frontend-port show \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "httpsPort" \
        --output table; then
        log "ERROR: HTTPS frontend port creation failed."
        exit 1
    fi
    
    # Configure backend pool to point to App Service
    log "Configuring Application Gateway backend pool..."
    
    az network application-gateway address-pool create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaBackendPool" \
        --servers "$WEB_APP_NAME.azurewebsites.net" \
        --output table
    
    # Create a custom health probe
    log "Creating health probe..."
    az network application-gateway probe create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaHealthProbe" \
        --protocol Https \
        --host "$WEB_APP_NAME.azurewebsites.net" \
        --path / \
        --interval 30 \
        --timeout 30 \
        --threshold 3 \
        --output table
    
    # Create HTTPS backend settings (with probe association)
    log "Creating HTTPS backend settings..."
    az network application-gateway http-settings create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaBackendSettings" \
        --port 443 \
        --protocol Https \
        --cookie-based-affinity Disabled \
        --host-name-from-backend-pool true \
        --probe "ztaHealthProbe" \
        --output table
    
    # Create HTTPS listener with custom hostname
    local custom_hostname="$DOMAIN_NAME"
    
    log "Creating HTTPS listener (initial)..."
    az network application-gateway http-listener create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaListener" \
        --frontend-port "httpsPort" \
        --ssl-cert "ztaTrustedWildCard" \
        --host-names "$custom_hostname" \
        --output table
    
    # Update listener to set HTTPS protocol
    log "Updating listener to set HTTPS protocol..."
    az network application-gateway http-listener update \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaListener" \
        --set protocol=Https \
        --output table
    
    # Create routing rule
    log "Creating routing rule..."
    az network application-gateway rule create \
        --gateway-name "$APP_GATEWAY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --name "ztaRouteRule1" \
        --http-listener "ztaListener" \
        --address-pool "ztaBackendPool" \
        --http-settings "ztaBackendSettings" \
        --priority 100 \
        --output table
    
    log "Application Gateway configured ✓"
}

create_azure_firewall() {
    log "Creating Azure Firewall public IP..."
    
    # Create public IP for Azure Firewall
    az network public-ip create \
        --name ztaFirewallPip \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --allocation-method Static \
        --sku Standard \
        --output table
    
    log "Creating Azure Firewall..."
    
    # Create Azure Firewall
    az network firewall create \
        --name mztaFirewall \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku AZFW_VNet \
        --tier Premium \
        --output table
    
    log "Creating firewall policy..."
    
    # Create firewall policy
    az network firewall policy create \
        --name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --sku Premium \
        --output table
    
    log "Configuring firewall policy settings..."
    
    # Get managed identity resource ID
    local identity_id=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query id -o tsv)
    
    # Verify Key Vault secret accessibility
    log "Verifying Key Vault secret accessibility..."
    if ! az keyvault secret show \
        --vault-name "$KEY_VAULT_NAME" \
        --name "ztaTrustedWildCard" \
        --query attributes.enabled \
        --output tsv | grep -q true; then
        log "ERROR: Key Vault secret 'ztaTrustedWildCard' is not accessible or not enabled."
        exit 1
    fi
    
    # Re-apply Key Vault permissions
    log "Re-applying Key Vault permissions for managed identity..."
    local identity_principal_id=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query principalId -o tsv)
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --object-id "$identity_principal_id" \
        --secret-permissions get \
        --certificate-permissions get \
        --output table
    
    # Add a delay to ensure propagation
    log "Waiting for Key Vault secret propagation..."
    sleep 30
    
    # Update firewall policy to enable TLS inspection with ports
    log "Enabling Explicit Proxy with TLS inspection..."
    az network firewall policy update \
        --name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --identity "$identity_id" \
        --key-vault-secret-id "https://$KEY_VAULT_NAME.vault.azure.net/secrets/ztaTrustedWildCard" \
        --set explicitProxy.enableExplicitProxy=true explicitProxy.httpPort=8082 explicitProxy.httpsPort=8444 \
        --output table
    
    log "Configuring firewall network rules..."
    
    # Add network rules
    az network firewall policy rule-collection-group create \
        --name ztaNetworkRuleCollection \
        --policy-name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --priority 100 \
        --output table
    
    az network firewall policy rule-collection-group rule add \
        --name AllowWeb \
        --collection-name ztaNetworkRuleCollection \
        --policy-name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --rule-type NetworkRule \
        --source-addresses "$APPGW_SUBNET_CIDR" \
        --destination-addresses "$APP_SUBNET_CIDR" \
        --destination-ports 443 \
        --protocols TCP \
        --action Allow \
        --priority 100 \
        --output table
    
    log "Configuring firewall application rules..."
    
    # Add application rules for HTTP/S traffic
    az network firewall policy rule-collection-group create \
        --name ztaApplicationRuleCollection \
        --policy-name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --priority 200 \
        --output table
    
    az network firewall policy rule-collection-group rule add \
        --name AllowWebTraffic \
        --collection-name ztaApplicationRuleCollection \
        --policy-name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --rule-type ApplicationRule \
        --source-addresses "$APPGW_SUBNET_CIDR" \
        --destination-fqdns "$WEB_APP_NAME.azurewebsites.net drcprakash.com" \
        --protocols http=80 https=443 \
        --action Allow \
        --priority 200 \
        --output table
    
    log "Associating firewall policy with Azure Firewall..."
    
    # Associate policy with firewall
    az network firewall update \
        --name mztaFirewall \
        --resource-group "$RESOURCE_GROUP" \
        --policy ztaFirewallPolicy \
        --output table
    
    log "Azure Firewall configured ✓"
}

create_azure_firewall() {
    log "Creating Azure Firewall public IP..."
    
    # Create public IP for Azure Firewall
    az network public-ip create \
        --name ztaFirewallPip \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --allocation-method Static \
        --sku Standard \
        --output table
    
    log "Creating Azure Firewall..."
    
    # Create Azure Firewall
    az network firewall create \
        --name mztaFirewall \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --sku AZFW_VNet \
        --tier Premium \
        --output table
    
    log "Creating firewall policy..."
    
    # Create firewall policy
    az network firewall policy create \
        --name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --sku Premium \
        --output table
    
    log "Configuring firewall policy settings..."
    
    # Get managed identity resource ID
    local identity_id=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query id -o tsv)
    
    # Update firewall policy to enable TLS inspection
    az network firewall policy update \
        --name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --identity "$identity_id" \
        --key-vault-secret-id "https://$KEY_VAULT_NAME.vault.azure.net/secrets/ztaTrustedWildCard" \
        --set explicitProxy.enableExplicitProxy=true \
        --output table
    
    log "Configuring firewall network rules..."
    
    # Add network rules
    az network firewall policy rule-collection-group create \
        --name ztaNetworkRuleCollection \
        --policy-name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --priority 100 \
        --output table
    
    az network firewall policy rule-collection-group rule add \
        --name AllowWeb \
        --collection-name ztaNetworkRuleCollection \
        --policy-name ztaFirewallPolicy \
        --resource-group "$RESOURCE_GROUP" \
        --rule-type NetworkRule \
        --source-addresses "$APPGW_SUBNET_CIDR" \
        --destination-addresses "$APP_SUBNET_CIDR" \
        --destination-ports 443 \
        --protocols TCP \
        --action Allow \
        --priority 100 \
        --output table
    
    log "Associating firewall policy with Azure Firewall..."
    
    # Associate policy with firewall
    az network firewall update \
        --name mztaFirewall \
        --resource-group "$RESOURCE_GROUP" \
        --policy ztaFirewallPolicy \
        --output table
    
    log "Azure Firewall configured ✓"
}

create_dns_record() {
    log "Creating DNS A record for the web application..."
    
    # Get Application Gateway public IP
    local appgw_public_ip=$(az network public-ip show \
        --name "ztaAppGWpip" \
        --resource-group "$RESOURCE_GROUP" \
        --query ipAddress -o tsv)
    
    log "Application Gateway public IP: $appgw_public_ip"
    
    # Create DNS A record for the root domain
    az network dns record-set a add-record \
        --resource-group "$RESOURCE_GROUP" \
        --zone-name "$DNS_ZONE_NAME" \
        --record-set-name "@" \
        --ipv4-address "$appgw_public_ip" \
        --output table
    
    log "DNS A record created: $DOMAIN_NAME -> $appgw_public_ip ✓"
}

create_network_security_groups() {
    log "Creating Network Security Groups for additional protection..."
    
    # NSG for App Service subnet
    az network nsg create \
        --name "nsg-app1" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output table
    
    # Allow HTTPS from Firewall subnet
    az network nsg rule create \
        --name "Allow_HTTPS_From_Firewall" \
        --nsg-name "nsg-app1" \
        --resource-group "$RESOURCE_GROUP" \
        --priority 300 \
        --source-address-prefixes "$FIREWALL_SUBNET_CIDR" \
        --source-port-ranges "*" \
        --destination-address-prefixes "*" \
        --destination-port-ranges "443" \
        --access Allow \
        --protocol Tcp \
        --output table
    
    # Deny all other traffic
    az network nsg rule create \
        --name "Deny_All_Traffic" \
        --nsg-name "nsg-app1" \
        --resource-group "$RESOURCE_GROUP" \
        --priority 310 \
        --source-address-prefixes "*" \
        --source-port-ranges "*" \
        --destination-address-prefixes "*" \
        --destination-port-ranges "*" \
        --access Deny \
        --protocol "*" \
        --output table
    
    # Associate NSG with App Service subnet
    az network vnet subnet update \
        --name "App1" \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$SPOKE_VNET_NAME" \
        --network-security-group "nsg-app1" \
        --output table
    
    log "Network Security Groups configured ✓"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "Starting Azure Zero Trust Infrastructure deployment..."
    log "This will take approximately 45-60 minutes to complete."
    
    # Prerequisites check
    check_prerequisites
    
    # Set up Azure context
    setup_subscription
    
    # Core infrastructure
    #create_resource_group
    #create_key_vault  # enable this only for first time
    #create_managed_identity
    
    # Network infrastructure
    #create_virtual_networks
    #create_dns_zone
    
    # Application services
    #create_app_service
    #create_application_gateway
    
    # Security services (longest step - ~30 minutes)
    create_azure_firewall
    
    # Network configuration
    create_route_tables
    create_dns_record
    create_network_security_groups
    
    # Deployment summary
    log "=========================================="
    log "DEPLOYMENT COMPLETED SUCCESSFULLY! ✓"
    log "=========================================="
    log ""
    log "Your Zero Trust infrastructure is now deployed with the following resources:"
    log "• Resource Group: $RESOURCE_GROUP"
    log "• Application Gateway: $APP_GATEWAY_NAME"
    log "• Azure Firewall: $FIREWALL_NAME (Premium)"
    log "• App Service: $WEB_APP_NAME"
    log "• Key Vault: $KEY_VAULT_NAME"
    log "• Web URL: https://$DOMAIN_NAME"
    log ""
    log "NEXT STEPS:"
    log "1. Update your domain's name servers to use Azure DNS"
    log "2. Wait for DNS propagation (up to 48 hours)"
    log "3. Test the application at: https://$DOMAIN_NAME"
    log ""
    log "IMPORTANT NOTES:"
    log "• All traffic flows: Internet -> App Gateway -> Firewall -> App Service"
    log "• TLS inspection is enabled on the firewall"
    log "• WAF protection is active on the Application Gateway"
    log "• Private endpoints ensure App Service is not publicly accessible"
    log ""
    log "To clean up all resources later, run:"
    log "az group delete --name $RESOURCE_GROUP --yes --no-wait"
}

# Run the main function
main "$@"
