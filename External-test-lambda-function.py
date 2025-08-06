import json
import boto3
import logging

# For CloudWatch Logs
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    threat_level = event.get('threat_level')
    action = event.get('recommended_action')
    user_id = event.get('user_id')
    
    
    logger.info(f"Received event: {json.dumps(event)}")

    #actions to be taken based on threat level
    if threat_level >= 0.8:
        action_taken = "Revoke/Terminate Session"
    elif 0.5 <= threat_level < 0.8:
        action_taken = "Require MFA"
    else:
        action_taken = "Allow"

    logger.info(f"Based on the threat level {threat_level}, the action taken is: {action_taken}")

    # IAM client
    iam_client = boto3.client('iam')
    
    # Policy arns for created policies
    allow_policy_arn = 'arn:aws:iam::405045611860:policy/AllowAccessPolicy'
    require_mfa_policy_arn = 'arn:aws:iam::405045611860:policy/RequireMFAPolicy'
    revoke_policy_arn = 'arn:aws:iam::405045611860:policy/RevokeAccessPolicy'
    
    # Getting current Policies
    attached_policies = iam_client.list_attached_user_policies(UserName=user_id)
    current_policies = [policy['PolicyArn'] for policy in attached_policies['AttachedPolicies']]
    

    policy_to_apply = None
    
    if action_taken == 'Allow':
        policy_to_apply = allow_policy_arn
    elif action_taken == 'Require MFA':
        policy_to_apply = require_mfa_policy_arn
    elif action_taken == 'Revoke/Terminate Session':
        policy_to_apply = revoke_policy_arn

    # If conflicting policy remvoe and apply new one
    for policy_arn in current_policies:
        if policy_arn != policy_to_apply:
            iam_client.detach_user_policy(UserName=user_id, PolicyArn=policy_arn)
            logger.info(f"Removed conflicting policy {policy_arn} from user {user_id}")
    

    iam_client.attach_user_policy(UserName=user_id, PolicyArn=policy_to_apply)
    logger.info(f"Applied policy {policy_to_apply} to user {user_id}")


    return {
        'statusCode': 200,
        'body': json.dumps(f"Action '{action_taken}' applied to user '{user_id}' based on threat level '{threat_level}'")
    }
