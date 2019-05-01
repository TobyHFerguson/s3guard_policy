# Given an Altus cluster name and an AWS folder, suggest the policy that will prevent S3Guard confusion

# cluster -> Environment -> IAM Instance Profile -> Role id
# get a cluster environment's crn

# Test that the S3_BUCKET exists
function bucket_exists_p() {
    ${AWS:?} s3api list-buckets --query "Buckets[?Name=='${S3_BUCKET:?}'].Name" | grep -q "${S3_BUCKET:?}"
}

# return the policy, in json format, given a cluster name
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

function error() {
    echo "$(basename $0): ERROR: $*" 1>&2
    echo 1>&2
    usage
    exit 1;
}

# return the Aws IAM Role Id given a cluster name
function getawsroleid() {
    local pname=$(getinstanceprofilename ${CLUSTER_NAME:?})
    [ -z "${pname}" ] && { return 20; }
    ${AWS:?} iam get-instance-profile --instance-profile-name ${pname:?} --output json |
	jq -r '.InstanceProfile.Roles[0].RoleId'
}


# return the json cluster description given the cluster name
function getclusterdescription() {
    local cd=$(${ALTUS:?} dataeng describe-cluster --cluster-name ${CLUSTER_NAME:?} 2>/dev/null || ${ALTUS:?} dataware describe-cluster --cluster-name ${CLUSTER_NAME:?} 2>/dev/null)
    if [ -z "${cd}" ]
    then
	error "Couldn't find cluster named ${CLUSTER_NAME:?}"
    else
	echo $cd
    fi	
}

# return the environment crn given the cluster name
function getenvironmentcrn() {
    getclusterdescription | jq -r '.cluster.environmentCrn'
}

# return the instance profile name given a cluster
function getinstanceprofilename() {
    local cluster_crn=$(getenvironmentcrn ${CLUSTER_NAME:?})
    [ -z "${cluster_crn}" ] && { return 15; }
    ${ALTUS:?} environments list-environments |
	jq -r --arg CRN  ${cluster_crn:?} '.environments[] | select(.crn == $CRN) | .awsDetails.instanceProfileName'
}

# Handle the case when the old and new policies have lexical differences
function handle_differing_policies() {
    cat <<EOF
The two policies differ. Here's an sdiff(1) output, common lines on the left, changed lines on the right

EOF
    sdiff -W  -l  <(echo $opolicy | jq '.') <(echo $policy | jq '.')
    replace_policy
}

# Handle the case when the old and new policies are lexically identical
function handle_identical_policies() {
    cat <<EOF
There's nothing to do - the old and new policies are the same
EOF
}

# Handle the situation where there's no bucket to write the policy to
function handle_no_bucket() {
    cat <<EOF
The required policy is:

$(echo $policy | jq '.')

However the bucket "${S3_BUCKET:?}" doesn't exist, so the policy cannot be written to that bucket.
EOF
}

# Handle the case when there is no old policy
function handle_no_old_policy() {
    cat <<EOF
There is no old policy for ${BUCKET_FOLDER:?} 

The new policy to be implemented for ${BUCKET_FOLDER:?} is:

$(echo $policy | jq '.')

EOF
    replace_policy
}

function usage() {
    cat 1>&2 <<EOF
Usage: $(basename $0) [-l altus profile] [-w aws profile] cluster s3_url

       Given an Altus cluster name and an AWS folder, create the policy that will prevent S3Guard confusion

       -l altus profile: Use the given profile for altus
       -w aws profile:   Use the given profile for aws
EOF
}

# Offer to replace/update the policy iff the bucket exists
function replace_policy() {
    read -p "Put the policy in place for the bucket? (Yes/No): " answer
    if [ "${answer,,}" == "yes" ]
    then
	write_policy
    fi
}

# Write the bucket policy
function write_policy() {
    if ${AWS:?} s3api put-bucket-policy --bucket ${S3_BUCKET:?} --policy "${policy}"
    then
	echo "Policy written"
    else
	echo "There was an error replacing the old policy with the new one" 1>&2
	exit 1
    fi
}

### MAIN
ALTUS=altus
AWS=AWS

# Handle the -l altus_profile and -w aws_profile options
while getopts ":l:w:" opt
do
    case ${opt} in
	l) ALTUS="altus --profile $OPTARG";;
	w) AWS="aws --profile $OPTARG";;
	:) error "Invalid option: ${OPTARG} requires an argument";;
	\?) error "Unknown option: -${OPTARG}";;
    esac
done
shift $((OPTIND -1))

# Prevent updates to ALTUS and AWS commands
typeset -r ALTUS
typeset -r AWS

# Check for the cluster and s3 url args
[ $# -ne 2 ] && { error "Unexpected number of parameters: $#; Expected 2"; }

# Provide for easy to remember names
readonly CLUSTER_NAME=${1:?"No cluster name provided"}
readonly S3_FOLDER_URL=${2:?"No S3 folder URL provided"}
# We'll accept any kind of url and assume that the bucket/folder stuff is after the first '*//'
readonly BUCKET_FOLDER=${S3_FOLDER_URL#*://}
readonly S3_BUCKET=${BUCKET_FOLDER%%/*}

# Set this so that failures in pipes will be signalled properly
set -o pipefail

 # Will be null if no policy, or no bucket
#readonly opolicy=$(${AWS:?} s3api get-bucket-policy --bucket ${S3_BUCKET:?} 2>/dev/null)
policy=$(create_policy_json) || { exit $?; }

# Enter here with a possibly null old policy, and a new policy.
# Figure out what the situation is and prompt the user for input

if bucket_exists_p
then
    opolicy=$(${AWS:?} s3api get-bucket-policy --bucket ${S3_BUCKET:?} 2>/dev/null)
    if [ -z "$opolicy" ]
    then
	handle_no_old_policy
    elif cmp -s <(echo "$opolicy" | jq '.') <(echo "$policy" | jq '.')
    then
	handle_identical_policies
    else
	handle_differing_policies
    fi
else
    handle_no_bucket
fi
