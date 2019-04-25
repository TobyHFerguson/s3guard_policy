# Given an Altus cluster name and an AWS folder, suggest the policy that will prevent S3Guard confusion

# cluster -> Environment -> IAM Instance Profile -> Role id
# get a cluster environment's crn

readonly CLUSTER_NAME=${1:?"No cluster name provided"}
readonly S3_FOLDER_URL=${2:?"No S3 folder URL provided"}
readonly BUCKET_FOLDER=${S3_FOLDER_URL#s3*://}
readonly S3_BUCKET=${BUCKET_FOLDER%%/*}

# Set this so that failures in pipes will be signalled properly
set -o pipefail

function getenvironmentcrn() {
    altus dataeng describe-cluster --cluster-name ${CLUSTER_NAME:?} | jq -r '.cluster.environmentCrn'
}

# Get the instance profile name given a cluster
function getinstanceprofilename() {
    local cluster_crn=$(getenvironmentcrn ${CLUSTER_NAME:?})
    [ -z "${cluster_crn}" ] && { return 15; }
    altus environments list-environments |
	jq -r --arg CRN  ${cluster_crn:?} '.environments[] | select(.crn == $CRN) | .awsDetails.instanceProfileName'
}

# Get the Aws IAM Role Id given a clusterman

function getawsroleid() {
    local pname=$(getinstanceprofilename ${CLUSTER_NAME:?})
    [ -z "${pname}" ] && { return 20; }
    aws iam get-instance-profile --instance-profile-name ${pname:?} --output json |
	jq -r '.InstanceProfile.Roles[0].RoleId'
}


function create_policy_json() {
    local ari=$(getawsroleid)
    [ -z "${ari}" ] && { return 25; }
    cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
	{
	    "Sid": "Ensure only hdfs path can modify ${BUCKET_FOLDER}",
	    "Effect": "Deny",
	    "Principal": {
		"AWS": "*"
	    },
	    "Action": "s3:DeleteObject",
	    "Resource": [
		"arn:aws:s3:::${BUCKET_FOLDER:?}/*",
		"arn:aws:s3:::${BUCKET_FOLDER:?}"
	    ],
	    "Condition": {
		"StringNotLike": {
		    "aws:userId": "${ari}:*"
		}
	    }
	}
    ]
}
EOF
}

function write_policy() {
    if aws s3api put-bucket-policy --bucket ${S3_BUCKET:?} --policy "${policy}"
    then
	echo "Policy written"
    else
	echo "There was an error replacing the old policy with the new one" 1>&2
	exit 1
    fi
}

function replace_policy() {
    read -p "Put the policy in place for the bucket? (Yes/No): " answer
    if [ "${answer,,}" == "yes" ]
    then
	write_policy
    fi
}

 # Will be null if no policy
readonly opolicy=$(aws s3api get-bucket-policy --bucket ${S3_BUCKET:?} 2>/dev/null)
policy=$(create_policy_json) || { exit $?; }

# Enter here with a possibly null old policy, and a new policy.
# Figure out what the situation is and prompt the user for input

function handle_no_old_policy() {
    cat <<EOF
There is no old policy for ${BUCKET_FOLDER:?} 

The new policy to be implemented for ${BUCKET_FOLDER:?} is:

$(echo $policy | jq '.')

EOF
    replace_policy
}

function handle_identical_policies() {
    cat <<EOF
There's nothing to do - the old and new policies are the same
EOF
}

function handle_differing_policies() {
    cat <<EOF
The two policies differ. Here's an sdiff(1) output, old on the left, changed on the right

EOF
    sdiff -W  -l  <(echo $opolicy | jq '.') <(echo $policy | jq '.')
    replace_policy
}

if [ -z "$opolicy" ]
then
    handle_no_old_policy
elif cmp -s <(echo "$opolicy" | jq '.') <(echo "$policy" | jq '.')
then
    handle_identical_policies
else
    handle_differing_policies
fi

