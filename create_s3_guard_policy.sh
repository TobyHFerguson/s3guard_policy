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
    local pname=$(getinstanceprofilename)
    [ -z "${pname}" ] && { return 20; }
    ${AWS:?} iam get-instance-profile --instance-profile-name ${pname:?} --output json |
	jq -r '.InstanceProfile.Roles[0].RoleId'
}


# return the json cluster description given the cluster name
function getclusterdescription() {
    ${ALTUS:?} dataeng describe-cluster --cluster-name ${NAME:?} 2>/dev/null || ${ALTUS:?} dataware describe-cluster --cluster-name ${NAME:?} 2>/dev/null
}

# get the environment name from NAME, first treating it as a cluster name, otherwise it is the NAME
function getenvironmentcrn() {
    local cd=$(getclusterdescription)
    if [ ! -z "$cd" ]
    then
	echo $cd | jq -r '.cluster.environmentCrn'
    fi
}

# Get the instance profile name given a name which could be a cluster or an environment name
function getinstanceprofilename() {
    local ipn
    case $NAMETYPE in
	"either" ) ipn=$(getinstanceprofilenamefromclustername || getinstanceprofilenamefromenvironmentname );
		   [ -z "${ipn}" ] && { error "No AWS cluster nor environment named $NAME found"; }
		   ;;
	"cluster") ipn=$(getinstanceprofilenamefromclustername );
		   [ -z "${ipn}" ] && { error "No AWS cluster named $NAME found"; }
		   ;;
	"environment") ipn=$(getinstanceprofilenamefromenvironmentname);
		       [ -z "${ipn}" ] && { error "No AWS environment named $NAME found"; }
		       ;;
	*) error "Internal error. Unexpected NAMETYPE: $NAMETYPE";;
    esac
    echo $ipn
}

# return the instance profile name given a cluster name
function getinstanceprofilenamefromclustername() {
    local env_crn=$(getenvironmentcrn)
    [ -z "${env_crn}" ] && { return 15; }
    ${ALTUS:?} environments list-environments |
	jq -r --arg CRN  ${env_crn:?} '.environments[] | select(.crn == $CRN) | select(.type == "AWS") | .awsDetails.instanceProfileName'
}

# return the instance profile name from an environment name
function getinstanceprofilenamefromenvironmentname() {
    ${ALTUS:?} environments list-environments |
	jq -r --arg ENAME  ${NAME} '.environments[] | select(.environmentName == $ENAME) | select(.type == "AWS") | .awsDetails.instanceProfileName'
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
Usage: $(basename $0) [-c | -e ] [-l altus profile] [-w aws profile] name s3_url

       Given either an Altus cluster or environment name (cluster is
       looked for first, then an environment, unless the -c|-e flag
       is given) and an AWS folder, create the policy that will
       prevent S3Guard confusion.

       -c indicate that name is the name of a cluster. It is an error 
          if this cluster cannot be found.
       -e indicate that name is the name of an environment. It is an 
          error if this environment cannot be found.
       -l altus profile: Use the given profile for altus
       -w aws profile:   Use the given profile for aws

       When neither the -c nor the -e flag is found search for a
       cluster first, and then an environment. It is an error if
       neither can be found using the given name.

       For any option, the last option found determines the value option.

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
NAMETYPE=either

# Handle the -l altus_profile and -w aws_profile options
while getopts ":cel:w:" opt
do
    case ${opt} in
	c) NAMETYPE=cluster;;
	e) NAMETYPE=environment;;
	l) ALTUS="altus --profile ${OPTARG}";;
	w) AWS="aws --profile ${OPTARG}";;
	:) error "Invalid option: ${OPTARG} requires an argument";;
	\?) error "Unknown option: -${OPTARG}";;
    esac
done
shift $((OPTIND -1))

# Prevent updates to variables defined above
typeset -r ALTUS
typeset -r AWS
typeset -r NAMETYPE


# Check for the cluster and s3 url args
[ $# -ne 2 ] && { error "Unexpected number of parameters: $#; Expected "; }

# Provide for easy to remember names
readonly NAME=$1
readonly S3_FOLDER_URL=$2
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
