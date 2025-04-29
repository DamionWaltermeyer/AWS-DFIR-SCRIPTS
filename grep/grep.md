# If nothing is configured except for cloudtrail.

### find where the cloudtrail logs are stored.
```
aws cloudtrail describe-trails --query 'trailList[*].{Name:Name, S3BucketName:S3BucketName}' --output table
```

### download the logs
```
aws s3 sync s3://cloudtrail-logs-yourbucket/AWSLogs/<account-id>/CloudTrail/us-east-1/2025/04/28/ ./cloudtrail_logs/
```

### decompress
```
cd cloudtrail_logs/ && gunzip *.gz 
```

### Grep the heck out of them

### for everything the key did
```
grep -i "<COMPROMISED_ACCESS_KEY_ID>" *.json
```
### for more granular logs
```
grep -i '"eventName":"CreateUser"' *.json
grep -i '"eventName":"CreateRole"' *.json
grep -i '"eventName":"AttachUserPolicy"' *.json
grep -i '"eventName":"PutUserPolicy"' *.json
```

### looking for instances they started
```
grep -i '"eventName":"RunInstances"' *.json
```

### looking for security group modifications
```
grep -i '"eventName":"AuthorizeSecurityGroupIngress"' *.json
grep -i '"eventName":"CreateSecurityGroup"' *.json
```

### Looking to see if they're in the console or just cli
```
grep -i '"eventName":"ConsoleLogin"' *.json
```

### build a list of possible IPs for attribution
```
grep -i '"sourceIPAddress"' *.json | sort | uniq
```


### an example on how to make it prettier if you want.
```
mkdir analysis_results

grep -i "<COMPROMISED_ACCESS_KEY_ID>" *.json > analysis_results/compromised_key_activity.txt
grep -i '"CreateUser"' *.json > analysis_results/created_users.txt
grep -i '"CreateRole"' *.json > analysis_results/created_roles.txt
grep -i '"RunInstances"' *.json > analysis_results/launched_instances.txt
grep -i '"AuthorizeSecurityGroupIngress"' *.json > analysis_results/sg_ingress_changes.txt
grep -i '"ConsoleLogin"' *.json > analysis_results/console_logins.txt
```
