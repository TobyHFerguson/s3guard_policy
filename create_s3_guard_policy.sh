# Script to restrict access to a folder that will be used for S3 guarded objects
# In other words, any meta-data changing actions on objects in this folder are denied
# to everyone except the IAM Role that is running on an S3 guarded cluster.

readonly INSTANCE_POLICY_ROLE_NAME=awsUsWest2SeInstanceProfile
readonly INSTANCE_POLICY_ARN="arn:aws:iam::007856030109:role/awsUsWest2SeInstanceProfile"
readonly S3_GUARD_FOLDER=S3GuardOnly
readonly S3_BUCKET=aabbcc33

ID=$(aws iam get-role --role-name awsUsWest2SeInstanceProfile --output json | jq -r '.Role.RoleId')

function create_policy_json() {
    cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
	{
	    "Sid": "Prevent inadvertent access to ${S3_BUCKET:?}/${S3_GUARD_FOLDER:?}",
	    "Effect": "Deny",
	    "Principal": {
		"AWS": "*"
	    },
	    "Action": [
		"s3:DeleteObject",
		"s3:GetObject"
	    ],
	    "Resource": [
		"arn:aws:s3:::${S3_BUCKET:?}/${S3_GUARD_FOLDER:?}/*",
		"arn:aws:s3:::${S3_BUCKET:?}/${S3_GUARD_FOLDER:?}"
	    ],
	    "Condition": {
		"StringNotLike": {
		    "aws:userId": [
			"${ID:?}:*"
		    ]
		}
	    }
	}
    ]
}
EOF
}

policy=$(create_policy_json | jq '.')

echo
echo The policy to be implemented for ${S3_BUCKET:?}:
echo $policy | jq '.'

aws s3api put-bucket-policy --bucket ${S3_BUCKET:?} --policy "${policy}" || {
    echo
    echo Failing policy:
    echo
    echo $policy | jq '.' 
    }

