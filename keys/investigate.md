
### contain

# for if a key is disclosed.
# if you have the repo cloned and want to search it for other exposures.
```git log -p -- all | grep -i 'aws_access_key_id'```


#Get a list of keys if you don't have it already
```aws iam list-access-keys```

# Disable the disclosed key
```aws iam update-access-key --access-key-id <ACCESS_KEY_ID> --status Inactive --user-name <USER_NAME>```

# List users
```aws iam list-users```
# to list all the IAM users created recently (set your own date, go back to at least the key disclosure date, but add a week or three if you can)
```aws iam list-users --query 'Users[?CreateDate>=`2025-04-28T00:00:00Z`]' --output table```
#list all the new roles
```aws iam list-roles --query 'Roles[?CreateDate>=`2025-04-28T00:00:00Z`]' --output table```
#list all the new policies
```aws iam list-policies --scope Local --query 'Policies[?CreateDate>=`2025-04-28T00:00:00Z`]' --output table```
#list all the new access keys since that date
```for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  echo "Access keys for user $user"
  aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[?CreateDate>=`2025-04-28T00:00:00Z`]' --output table
done```



# Lock down - If the disclosed key made other keys deactivate user-created access keys
```aws iam update-access-key --access-key-id <SUSPICIOUS_KEY> --status Inactive --user-name <SUSPICIOUS_USER>```

### preserve evidence

#get the current IAM state to compare against further changes
```aws iam get-account-authorization-details > account-auth-details.json```


# List instances in a region to look for suspicious instances
```aws ec2 describe-instances --region <region-name>```

# Create snapshots of suspicious volumes
```aws ec2 create-snapshot --volume-id <volume-id> --description "snapshot of compromised instance"```

### Investigation

#if you've got your cloudtrail logs in S3, you can use athena to look for suspicious activity
```SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress, awsRegion
FROM cloudtrail_logs
WHERE (eventName = 'CreateUser' OR eventName = 'CreateAccessKey' OR eventName = 'RunInstances')
  AND eventTime > timestamp '2025-04-28 00:00:00'
ORDER BY eventTime DESC;```

#or you can use bash and the commandline to search for new instances across regions.
```for region in $(aws ec2 describe-regions --query "Regions[*].RegionName" --output text); do
  echo "Region: $region"
  aws ec2 describe-instances --region $region
done```

# to find everything the compromised key did
```aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<COMPROMISED_ACCESS_KEY_ID>```
OR
in Athena if you've got the logs
```SELECT eventTime, eventName, userIdentity.userName, sourceIPAddress, awsRegion, requestParameters
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'COMPROMISED_ACCESS_KEY_ID'
ORDER BY eventTime DESC;```






### Remediation

#you can delete the malicious / unwanted keys 
```aws iam delete-access-key --access-key-id <ATTACKER_KEY> --user-name <ATTACKER_USER>
aws iam delete-user --user-name <ATTACKER_USER>```

#terminate malcious instances. 
```aws ec2 terminate-instances --instance-ids <instance-id> --region <region-name>```

### breakglass SCP - Denies everything except read-only access to IAM, Orgs, S3 listing and cloudtrail
#this lets you investigate without them being able to advance.

```{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyAllActionsExceptListAndIAM",
            "Effect": "Deny",
            "NotAction": [
                "iam:List*",
                "iam:Get*",
                "organizations:Describe*",
                "organizations:List*",
                "s3:Get*",
                "s3:List*",
                "cloudtrail:LookupEvents",
                "cloudtrail:Describe*",
                "cloudtrail:Get*"
            ],
            "Resource": "*"
        }
    ]
}
```

# First, create the SCP from above.
```aws organizations create-policy \
  --name "EmergencyLockdown" \
  --description "Deny all actions except for read-only incident response" \
  --type SERVICE_CONTROL_POLICY \
  --content file://EmergencyLockdown.json```

# Then attach it to the affected account
```aws organizations attach-policy \
  --policy-id <PolicyId> \
  --target-id <AccountId>```



