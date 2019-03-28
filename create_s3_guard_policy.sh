readonly INSTANCE_POLICY_ROLE_NAME=awsUsWest2SeInstanceProfile
readonly INSTANCE_POLICY_ARN="arn:aws:iam::007856030109:role/awsUsWest2SeInstanceProfile"
readonly S3_GUARD_FOLDER=S3GuardOnly
readonly S3_BUCKET=aabbcc11

ID=$(aws iam get-role --role-name awsUsWest2SeInstanceProfile --output json | jq -r '.Role.RoleId')

function create_policy_json() {
    cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
	{
	    "Sid": "Prevent inadventent access to S3 Guard Folder",
	    "Effect": "Deny",
	    "Principal": {
		"AWS": "*"
	    },
	    "Action": [
		"s3:DeleteObject",
		"s3:GetObject",
		"s3:PutObject"
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
aws s3api put-bucket-policy --bucket ${S3_BUCKET:?} --policy "${policy}"

