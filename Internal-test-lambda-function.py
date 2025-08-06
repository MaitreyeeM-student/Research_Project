import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # incoming event
    threat_level = event.get('threat_level')
    action = event.get('recommended_action')
    user_id = event.get('user_id')
    
    
    logger.info(f"Received event: {json.dumps(event)}")

    # conditions
    if threat_level >= 0.8:
        action_taken = "Revoke/Terminate Session"
    elif 0.5 <= threat_level < 0.8:
        action_taken = "Require MFA"
    else:
        action_taken = "Allow"

    logger.info(f"Based on the threat level {threat_level}, the action taken is: {action_taken}")

    # IAM client 
    iam_client = boto3.client('iam')
    
    
    allow_policy_arn = 'arn:aws:iam::405045611860:policy/AllowAccessPolicy'
    require_mfa_policy_arn = 'arn:aws:iam::405045611860:policy/RequireMFAPolicy'
    revoke_policy_arn = 'arn:aws:iam::405045611860:policy/RevokeAccessPolicy'
    
    # exsiting policies
    attached_policies = iam_client.list_attached_user_policies(UserName=user_id)
    current_policies = [policy['PolicyArn'] for policy in attached_policies['AttachedPolicies']]
    
    if action_taken == 'Allow':
        if allow_policy_arn in current_policies:
            logger.info(f"User {user_id} already has the Allow Access policy.")
        else:
            
            for policy_arn in current_policies: #remove exsisting conflicts
                if policy_arn not in [allow_policy_arn]:
                    iam_client.detach_user_policy(UserName=user_id, PolicyArn=policy_arn)
                    logger.info(f"Removed conflicting policy {policy_arn} from user {user_id}")
            iam_client.attach_user_policy(UserName=user_id, PolicyArn=allow_policy_arn)
            logger.info(f"Access allowed to user {user_id}")
    
    elif action_taken == 'Require MFA':
        if require_mfa_policy_arn in current_policies:
            logger.info(f"User {user_id} already has the MFA policy.")
        else:
            
            for policy_arn in current_policies:
                if policy_arn not in [require_mfa_policy_arn]:
                    iam_client.detach_user_policy(UserName=user_id, PolicyArn=policy_arn)
                    logger.info(f"Removed conflicting policy {policy_arn} from user {user_id}")
            iam_client.attach_user_policy(UserName=user_id, PolicyArn=require_mfa_policy_arn)
            logger.info(f"User {user_id} now requires MFA to access")
    
    elif action_taken == 'Revoke/Terminate Session':
        if revoke_policy_arn in current_policies:
            logger.info(f"User {user_id} already has the Revoke Access policy.")
        else:
    
            for policy_arn in current_policies:
                if policy_arn not in [revoke_policy_arn]:
                    iam_client.detach_user_policy(UserName=user_id, PolicyArn=policy_arn)
                    logger.info(f"Removed conflicting policy {policy_arn} from user {user_id}")
            iam_client.attach_user_policy(UserName=user_id, PolicyArn=revoke_policy_arn)
            logger.info(f"Access revoked for user {user_id}")
    

    return {
        'statusCode': 200,
        'body': json.dumps(f"Action '{action_taken}' applied to user '{user_id}' based on threat level '{threat_level}'")
    }
