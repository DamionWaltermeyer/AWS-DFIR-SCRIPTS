#!/bin/bash

# Set investigation start date
START_DATE="2025-04-28T00:00:00Z"

# Create output folder
OUTPUT_DIR="aws_ir_threat_hunt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Collecting AWS regions..."
REGIONS=$(aws ec2 describe-regions --query "Regions[*].RegionName" --output text)

# Set tag for incident
INCIDENT_TAG_KEY="IncidentResponse"
INCIDENT_TAG_VALUE="Compromised"

# Define sensitive ports to watch
SENSITIVE_PORTS=(22 3389 3306 5432)

function collect_vpcs {
    for region in $REGIONS; do
        echo "[*] Collecting VPCs in $region"
        aws ec2 describe-vpcs --region "$region" --query "Vpcs[*].{VpcId:VpcId,IsDefault:IsDefault,Tags:Tags}" --output json >> "$OUTPUT_DIR/vpcs_$region.json"
    done
}

function collect_subnets {
    for region in $REGIONS; do
        echo "[*] Collecting Subnets in $region"
        aws ec2 describe-subnets --region "$region" --query "Subnets[*].{SubnetId:SubnetId,VpcId:VpcId,Tags:Tags}" --output json >> "$OUTPUT_DIR/subnets_$region.json"
    done
}

function collect_instances_and_tag {
    for region in $REGIONS; do
        echo "[*] Collecting Instances in $region"
        instances=$(aws ec2 describe-instances --region "$region" --query 'Reservations[*].Instances[*].{InstanceId:InstanceId,LaunchTime:LaunchTime,State:State.Name,Tags:Tags}' --output json)
        echo "$instances" >> "$OUTPUT_DIR/instances_$region.json"

        # Tag instances launched after START_DATE
        instance_ids=$(echo "$instances" | jq -r --arg START_DATE "$START_DATE" '.[][] | select(.LaunchTime > $START_DATE) | .InstanceId')

        for instance_id in $instance_ids; do
            echo "[!] Tagging instance $instance_id as potentially compromised"
            aws ec2 create-tags --region "$region" --resources "$instance_id" --tags Key=$INCIDENT_TAG_KEY,Value=$INCIDENT_TAG_VALUE
        done
    done
}

function collect_security_groups_and_hunt {
    for region in $REGIONS; do
        echo "[*] Collecting and hunting Security Groups in $region"
        sgs=$(aws ec2 describe-security-groups --region "$region" --output json)
        echo "$sgs" >> "$OUTPUT_DIR/security_groups_$region.json"

        # Analyze security groups
        echo "$sgs" | jq -c '.SecurityGroups[]' | while read sg; do
            group_id=$(echo "$sg" | jq -r '.GroupId')
            group_name=$(echo "$sg" | jq -r '.GroupName')

            for port in "${SENSITIVE_PORTS[@]}"; do
                open_rule=$(echo "$sg" | jq --argjson port "$port" '.IpPermissions[]? | select(.FromPort==$port and .IpRanges[]?.CidrIp=="0.0.0.0/0")')

                if [ ! -z "$open_rule" ]; then
                    echo "[!!!] Security Group $group_name ($group_id) allows unrestricted access to port $port"
                    echo "$group_id (Port $port)" >> "$OUTPUT_DIR/suspicious_security_groups.txt"
                fi
            done
        done
    done
}

function collect_iam_users_roles_policies {
    echo "[*] Collecting IAM Users"
    aws iam list-users --query "Users[?CreateDate>=\`$START_DATE\`]" --output json > "$OUTPUT_DIR/iam_users_recent.json"

    echo "[*] Collecting IAM Roles"
    aws iam list-roles --query "Roles[?CreateDate>=\`$START_DATE\`]" --output json > "$OUTPUT_DIR/iam_roles_recent.json"

    echo "[*] Collecting IAM Policies"
    aws iam list-policies --scope Local --query "Policies[?CreateDate>=\`$START_DATE\`]" --output json > "$OUTPUT_DIR/iam_policies_recent.json"
}

function collect_access_keys {
    echo "[*] Collecting Access Keys created recently"
    USERS=$(aws iam list-users --query 'Users[*].UserName' --output text)
    for user in $USERS; do
        aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?CreateDate>=\`$START_DATE\`]" --output json >> "$OUTPUT_DIR/access_keys_recent.json"
    done
}

function collect_cloudtrail_by_accesskey {
    echo "[*] Collecting CloudTrail events for compromised access key..."
    read -p "Enter the compromised Access Key ID: " COMPROMISED_KEY
    aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$COMPROMISED_KEY" --output json > "$OUTPUT_DIR/cloudtrail_events_compromised_key.json"
}

# MAIN COLLECTION
collect_vpcs
collect_subnets
collect_instances_and_tag
collect_security_groups_and_hunt
collect_iam_users_roles_policies
collect_access_keys
collect_cloudtrail_by_accesskey

echo "[*] All data and threat hunting findings saved in folder: $OUTPUT_DIR"
