# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging
import json
import copy

from huaweicloudsdkcore.exceptions import exceptions

from obs import ACL

from c7n.utils import type_schema, set_annotation, local_session,\
format_string_values
from c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from c7n_huaweicloud.provider import resources
from c7n_huaweicloud.query import QueryResourceManager, TypeInfo

from c7n.filters import Filter

log = logging.getLogger("custodian.huaweicloud.resources.obs")


@resources.register('obs')
class Obs(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'obs'
        enum_spec = ("listBuckets", 'body.buckets', None)
        id = 'name'
        tag = False


class ObsSdkError():
    def __init__(self, code, message, request_id):
        self.error_code = code
        self.error_msg = message
        self.request_id = request_id
        self.encoded_auth_msg = ""


def get_obs_client(session_factory, bucket):
    session = local_session(session_factory)
    client = session.region_client(Obs.resource_type.service, bucket['location'])
    return client


def raise_exception(resp, method, bucket):
    log.error({"invoke method [": method, "] failed for bukcet ": bucket['name'],
               "request reason is ": resp.reason, " request id is": resp.requestId})
    sdk_error = ObsSdkError(resp.errorCode, resp.errorMessage, resp.requestId)
    raise exceptions.ClientRequestException(resp.status, sdk_error)


@Obs.action_registry.register('delete-wildcard-statements')
class DeleteWildcardStatement(HuaweiCloudBaseAction):
    """Action to delete wildcard policy statements from obs buckets

    :example:

    .. code-block:: yaml

            policies:
              - name: remove-wildcard-statements
                resource: huaweicloud.obs
                filters:
                  - type: wildcard-statements
                actions:
                  - type: delete-wildcard-statements
    """

    schema = type_schema('delete-wildcard-statements')

    def perform_action(self, bucket):
        bucket_name = bucket['name']
        p = bucket.get('Policy')
        if p is None:
            return

        if bucket.get(WildcardStatementFilter.annotation_key) is None:
            log.info("bucket %s has not wildcard policy" % bucket_name)
            return

        p = json.loads(p)
        new_statements = self.process_policy(p.get('Statement', []))

        p['Statement'] = new_statements
        self.update_statements(bucket, p)

        bucket['State'] = 'delete-wildcard-statements'
        bucket['newStatements'] = new_statements
        return bucket

    def process_policy(self, bucket_statements):
        new_statements = []
        for statement in bucket_statements:
            prinicipal_user = statement.get('Principal', {}).get("ID", [])
            action = statement.get('Action', [])
            if "*" in prinicipal_user or "*" in action:
                continue

            new_statements.append(statement)

        return new_statements

    def update_statements(self, bucket, policy):
        bucket_name = bucket['name']
        client = get_obs_client(self.manager.session_factory, bucket)

        if not policy['Statement']:
            resp = client.deleteBucketPolicy(bucket_name)
        else:
            resp = client.setBucketPolicy(bucket_name, json.dumps(policy))

        if resp.status > 300:
            raise_exception(resp, 'updateBucketPolicy', bucket)


@Obs.action_registry.register('set-bucket-encryption')
class SetBucketEncryption(HuaweiCloudBaseAction):
    """Enabling obs bucket encryption

    :example:

    .. code-block:: yaml

        policies:
            - name: encryption-bucket
              resource: huaweicloud.obs
              filters:
                - type: bucket-encryption
                  state: False
              actions:
                - type: set-bucket-encryption
                  crypto: AES256

    """
    schema = type_schema(
        'set-bucket-encryption',
        required=['encryption'],
        encryption={
            'type': 'object',
            'oneOf': [
                {
                    'required': ['crypto'],
                    'properties': {
                        'crypto': {'enum': ['AES256']}
                    }
                },
                {
                    'required': ['crypto'],
                    'properties': {
                        'crypto': {'enum': ['kms']},
                        'key': {'type': 'string'},
                        'kms_data_encryption': {'enum': ['SM4']}
                    }
                }
            ]
        }
    )

    def perform_action(self, bucket):
        bucket_name = bucket['name']

        cfg = self.data['encryption']

        client = get_obs_client(self.manager.session_factory, bucket)
        if cfg['crypto'] == 'AES256':
            resp = client.setBucketEncryption(bucket_name, 'AES256')
        else:
            key_id = cfg.get('key', None)
            if not key_id:
                resp = client.setBucketEncryption(bucket_name, 'kms')
            else:
                resp = client.setBucketEncryption(bucket_name, 'kms', key_id)

        if resp.status < 300:
            bucket['State'] = 'set-bucket-encryption'
            return bucket
        else:
            raise_exception(resp, 'setBucketEncryption', bucket)


@Obs.action_registry.register('delete-global-grants')
class DeleteGlobalGrants(HuaweiCloudBaseAction):
    """Deletes global grants associated to a obs bucket

    :example:

    .. code-block:: yaml

            policies:
              - name: obs-delete-global-grants
                resource: huaweicloud.obs
                filters:
                  - type: global-grants
                actions:
                  - type: delete-global-grants

    """

    schema = type_schema(
        'delete-global-grants')

    def perform_action(self, bucket):
        acl = bucket.get('Acl', {'grants': []})
        if not acl or not acl['grants']:
            return

        new_acl = self.filter_grants(acl, bucket.get('website', False))
        self.update_bucket_acl(bucket, new_acl)

    def filter_grants(self, acl, is_website_bucket):
        new_grants = []
        for grant in acl['grants']:
            grantee = grant.get('grantee', {})
            if not grantee:
                continue

            if 'group' not in grantee:
                new_grants.append(grant)
                continue

            if grantee['group'] not in ['Everyone']:
                new_grants.append(grant)
                continue

            if grant['permission'] == 'READ' and is_website_bucket:
                new_grants.append(grant)
                continue

        owner = acl['owner']
        return ACL(owner, new_grants)

    def update_bucket_acl(self, bucket, acl):
        client = get_obs_client(self.manager.session_factory, bucket)
        resp = client.setBucketAcl(bucket['name'], acl)

        if resp.status > 300:
            raise_exception(resp, 'setBucketAcl', bucket)


@Obs.action_registry.register('set-public-block')
class SetPublicBlock(HuaweiCloudBaseAction):
    """Action to update Public Access blocks on obs buckets

    If no action parameters are provided all settings will be set to the `state`, which defaults

    If action parameters are provided, those will be set and other extant values preserved.

    :example:

    .. code-block:: yaml

            policies:
              - name: public-block-enable-all
                resource: huaweicloud.obs
                filters:
                  - type: check-public-block
                actions:
                  - type: set-public-block

            policies:
              - name: public-block-disable-all
                resource: huaweicloud.obs
                filters:
                  - type: check-public-block
                actions:
                  - type: set-public-block
                    state: false

            policies:
              - name: public-block-enable-some
                resource: huaweicloud.obs
                filters:
                  - or:
                    - type: check-public-block
                      blockPublicAcls: false
                    - type: check-public-block
                      blockPublicPolicy: false
                actions:
                  - type: set-public-block
                    blockPublicAcls: true
                    blockPublicPolicy: true
    """

    schema = type_schema(
        'set-public-block',
        state={'type': 'boolean', 'default': True},
        blockPublicAcls={'type': 'boolean'},
        ignorePublicAcls={'type': 'boolean'},
        blockPublicPolicy={'type': 'boolean'},
        restrictPublicBuckets={'type': 'boolean'})

    keys = (
        'blockPublicPolicy', 'blockPublicAcls', 'ignorePublicAcls', 'restrictPublicBuckets')
    annotation_key = 'c7n:PublicAccessBlock'

    def perform_action(self, bucket):
        bucket_name = bucket['name']

        client = get_obs_client(self.manager.session_factory, bucket)

        config = dict(bucket.get(self.annotation_key, {key: False for key in self.keys}))
        if self.annotation_key not in bucket:
            resp = client.getBucketPublicAccessBlock(bucket_name)
            if resp.status < 300:
                config = resp.body
            else:
                error_code = resp.reason
                if error_code == 'Forbidden' or error_code == 'Method Not Allowed':
                    log.error('unsupport operate [BucketPublicAccessBlock]')
                raise_exception(resp, 'BucketPublicAccessBlock', bucket)

            bucket[self.annotation_key] = config

        key_set = [key for key in self.keys if key in self.data]
        if key_set:
            for key in key_set:
                config[key] = self.data.get(key)
        else:
            for key in self.keys:
                config[key] = self.data.get('state', True)

        resp = client.putBucketPublicAccessBlock(
            bucket_name, blockPublicAcls=config['blockPublicAcls'],
            ignorePublicAcls=config['ignorePublicAcls'],
            blockPublicPolicy=config['blockPublicPolicy'],
            restrictPublicBuckets=config['restrictPublicBuckets'])

        if resp.status > 300:
            raise_exception(resp, 'BucketPublicAccessBlock', bucket)


@Obs.action_registry.register("set-statements")
class SetPolicyStatement(HuaweiCloudBaseAction):
    """Action to add or update policy statements to obs buckets

    :example:

    .. code-block:: yaml

            policies:
              - name: force-obs-https
                resource: huaweicloud.obs
                filters:
                  - type: https-request-only
                actions:
                  - type: set-statements
                    statements:
                      - Sid: "DenyHttp"
                        Effect: "Deny"
                        Action: "*"
                        Principal:
                          ID: "*"
                        Resource: "{bucket_name}/*"
                        Condition:
                          Bool:
                            "SecureTransport": false
    """

    schema = type_schema(
        'set-statements',
        **{
            'statements': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'Sid': {'type': 'string'},
                        'Effect': {'type': 'string', 'enum': ['Allow', 'Deny']},
                        'Principal': {'anyOf': [{'type': 'string'},
                            {'type': 'object'}, {'type': 'array'}]},
                        'NotPrincipal': {'anyOf': [{'type': 'object'}, {'type': 'array'}]},
                        'Action': {'anyOf': [{'type': 'string'}, {'type': 'array'}]},
                        'NotAction': {'anyOf': [{'type': 'string'}, {'type': 'array'}]},
                        'Resource': {'anyOf': [{'type': 'string'}, {'type': 'array'}]},
                        'NotResource': {'anyOf': [{'type': 'string'}, {'type': 'array'}]},
                        'Condition': {'type': 'object'}
                    },
                    'required': ['Sid', 'Effect'],
                    'oneOf': [
                        {'required': ['Principal', 'Action', 'Resource']},
                        {'required': ['NotPrincipal', 'Action', 'Resource']},
                        {'required': ['Principal', 'NotAction', 'Resource']},
                        {'required': ['NotPrincipal', 'NotAction', 'Resource']},
                        {'required': ['Principal', 'Action', 'NotResource']},
                        {'required': ['NotPrincipal', 'Action', 'NotResource']},
                        {'required': ['Principal', 'NotAction', 'NotResource']},
                        {'required': ['NotPrincipal', 'NotAction', 'NotResource']}
                    ]
                }
            }
        }
    )

    def perform_action(self, bucket):
        target_statements = format_string_values(
            copy.deepcopy({s['Sid']: s for s in self.data.get('statements', [])}),
            **self.get_std_format_args(bucket))

        policy = bucket.get('Policy') or '{}'
        policy = json.loads(policy)
        bucket_statements = policy.setdefault('Statement', [])

        new_statement = []
        for s in bucket_statements:
            if s.get('Sid') not in target_statements:
                new_statement.append(s)
                continue

        new_statement.extend(target_statements.values())
        policy['Statement'] = new_statement
        policy = json.dumps(policy)

        bucket['newPolicy'] = policy

        client = get_obs_client(self.manager.session_factory, bucket)
        resp = client.setBucketPolicy(bucket['name'], policy)
        if resp.status > 300:
            raise_exception(resp, 'setBucketPolicy', bucket)

    def get_std_format_args(self, bucket):
        return {
            'bucket_name': bucket['name'],
            'bucket_region': bucket['location']
        }


# ----------------------OBS Fileter-------------------------------------------

@Obs.filter_registry.register("wildcard-statements")
class WildcardStatementFilter(Filter):
    """Filters for all obs buckets that include wildcard principals in bucket policy.
    such as "Principal": "*", or wildcard actions, such as "Action": "*".

    :example:

    .. code-block:: yaml

       policies:
         - name: remove-wildcard-statements
           resource: huaweicloud.obs
           filters:
            - type: wildcard-statements
           actions:
            - delete-wildcard-statements

    """

    schema = type_schema('wildcard-statements')

    annotation_key = 'c7n:WildcardStatements'

    def process(self, buckets, event=None):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = list(filter(None, list(results)))
            return results

    def process_bucket(self, bucket):
        self.get_bucket_policy(bucket)
        return self.filter_include_wildcard_statement_bucket_policy(bucket)

    def filter_include_wildcard_statement_bucket_policy(self, bucket):
        policy = bucket.get('Policy') or '{}'
        if not policy:
            log.info("bucket not config bucket policy")
            return None

        policy = json.loads(policy)
        bucket_statements = policy.setdefault('Statement', [])

        result = []
        for statement in bucket_statements:
            prinicipal_user = statement.get('Principal', {}).get("ID", [])
            action = statement.get('Action', [])
            if "*" in prinicipal_user or "*" in action:
                result.append(statement)

        if result:
            set_annotation(bucket, self.annotation_key, result)
            return bucket

        return None

    def get_bucket_policy(self, bucket):
        client = get_obs_client(self.manager.session_factory, bucket)
        resp = client.getBucketPolicy(bucket['name'])

        if resp.status < 300:
            policy = resp.body.policyJSON
            bucket['Policy'] = policy
        else:
            if 'NoSuchBucketPolicy' == resp.errorCode:
                bucket['Policy'] = {}
            else:
                raise_exception(resp, 'getBucketPolicy', bucket)


@Obs.filter_registry.register("bucket-encryption")
class BucketEncryptionStateFilter(Filter):
    """Filters OBS buckets that not encrypted

    :example:

    .. code-block:: yaml

        policies:
            - name: encryption-bucket
              resource: huaweicloud.obs
              filters:
                - type: bucket-encryption
                  state: False

    """

    schema = type_schema(
        'bucket-encryption',
        state={'type': 'boolean'},
        crypto={'enum': ['kms', 'AES256']},
        required=['state']
    )

    annotation_key = 'c7n:BucketEncryptionCrypto'

    def process(self, buckets, event=None):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = list(filter(None, list(results)))
            return results

    def process_bucket(self, bucket):
        target_state = self.data.get('state', False)
        target_crypto = self.data.get('crypto', None)

        current_crypto = self.get_encryption_crypto(bucket)
        bucket[self.annotation_key] = current_crypto

        if not target_state:
            if target_crypto is None and current_crypto is None:
                return bucket

            if target_crypto is not None and target_crypto != current_crypto:
                return bucket
        else:
            if target_crypto is None and current_crypto is not None:
                return bucket

            if target_crypto is not None and current_crypto is not None \
            and target_crypto == current_crypto:
                return bucket
        return None

    def get_encryption_crypto(self, bucket):
        client = get_obs_client(self.manager.session_factory, bucket)
        resp = client.getBucketEncryption(bucket['name'])

        if resp.status < 300:
            encryption = resp.body.encryption

            return encryption
        else:
            error_code = resp.errorCode
            if 'NoSuchEncryptionConfiguration' == error_code:
                return None
            else:
                raise_exception(resp, 'getBucketEncryption', bucket)


@Obs.filter_registry.register('global-grants')
class GlobalGrantsFilter(Filter):
    """Filters for all obs buckets that have global-grants

    *Note* by default this filter allows for read access
    if the bucket has been configured as a website. This
    can be disabled per the example below.

    :example:

    .. code-block:: yaml

       policies:
         - name: remove-global-grants
           resource: huaweicloud.obs
           filters:
            - type: global-grants
           actions:
            - type: delete-global-grants

    """

    schema = type_schema(
        'global-grants',
        operator={'type': 'string', 'enum': ['or', 'and']},
        allow_website={'type': 'boolean'},
        permissions={
            'type': 'array',
            'items': {
                'type': 'string',
                'enum': ['READ', 'WRITE', 'WRITE_ACP', 'READ_ACP', 'FULL_CONTROL']}
            })

    annotation_key = 'c7n:GlobalPermissions'

    def process(self, buckets, event=None):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = list(filter(None, list(results)))
            return results

    def process_bucket(self, bucket):
        results = []
        allow_website = self.data.get('allow_website', True)
        perms = self.data.get('permissions', [])

        client = get_obs_client(self.manager.session_factory, bucket)
        self.query_bucket_acl(bucket, client)

        for grant in bucket['Acl']['grants']:
            if 'group' not in grant.get('grantee', {}):
                continue

            if grant['grantee']['group'] not in ['Everyone']:
                continue

            if allow_website and grant['permission'] == 'READ' and \
                self.is_website_bucket(bucket, client=client):
                print("is website bucket")
                continue

            if not perms or (perms and grant['permission'] in perms):
                results.append(grant['permission'])

        if results:
            set_annotation(bucket, 'globalPermissions', results)
            return bucket

        return None

    def query_bucket_acl(self, bucket, client):
        resp = client.getBucketAcl(bucket['name'])
        if resp.status < 300:
            acl = resp.body
            bucket['Acl'] = acl
        else:
            raise_exception(resp, 'getBucketWebsite', bucket)

    def is_website_bucket(self, bucket, client):
        resp = client.getBucketWebsite(bucket['name'])
        if resp.status < 300:
            website_config = resp.body
            if 'indexDocument' in website_config:
                bucket['website'] = True
                return True
            else:
                bucket['website'] = False
                return False
        else:
            if 'NoSuchWebsiteConfiguration' == resp.errorCode:
                bucket['website'] = False
                return False
            else:
                raise_exception(resp, 'getBucketWebsite', bucket)


@Obs.filter_registry.register("check-public-block")
class FilterPublicBlock(Filter):
    """Filter for obs bucket public blocks

    If no filter paramaters are provided it checks to see if any are unset or False.

    If parameters are provided only the provided ones are checked.

    :example:

    .. code-block:: yaml

            policies:
              - name: CheckForPublicAclBlock-Off
                resource: huaweicloud.obs
                filters:
                  - type: check-public-block
                    blockPublicAcls: true
                    blockPublicPolicy: true
    """

    schema = type_schema(
        'check-public-block',
        blockPublicAcls={'type': 'boolean'},
        ignorePublicAcls={'type': 'boolean'},
        blockPublicPolicy={'type': 'boolean'},
        restrictPublicBuckets={'type': 'boolean'})

    keys = (
        'blockPublicPolicy', 'blockPublicAcls', 'ignorePublicAcls', 'restrictPublicBuckets')
    annotation_key = 'c7n:PublicAccessBlock'

    def process(self, buckets, event=None):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = list(filter(None, list(results)))
            return results

    def process_bucket(self, bucket):
        bucket_name = bucket['name']

        config = dict(bucket.get(self.annotation_key, {key: False for key in self.keys}))
        if self.annotation_key not in bucket:
            client = get_obs_client(self.manager.session_factory, bucket)
            resp = client.getBucketPublicAccessBlock(bucket_name)
            if resp.status < 300:
                config = resp.body
            else:
                error_code = resp.reason
                if error_code == 'Forbidden' or error_code == 'Method Not Allowed':
                    log.error('unsupport operate [BucketPublicAccessBlock]')
                    return None
                raise_exception(resp, 'BucketPublicAccessBlock', bucket)

            bucket[self.annotation_key] = config

        is_match = self.matches_filter(config)

        if is_match:
            return bucket
        else:
            return None

    def matches_filter(self, config):
        key_set = [key for key in self.keys if key in self.data]
        if key_set:
            return all([self.data.get(key) is config[key] for key in key_set])
        else:
            return not all(config.values())


@Obs.filter_registry.register("https-request-only")
class SecureTransportFilter(Filter):
    """Find buckets with allow http protocol access

    :example:

    .. code-block:: yaml

            policies:
              - name: obs-bucket-https-request-only
                resource: huaweicloud.obs
                filters:
                  - type: https-request-only
                actions:
                    - type: set-statements
                      statements:
                        - Sid: DenyHttp
                          Effect: Deny
                          Principal:
                            ID: "*"
                          Action: "*"
                          Resource:
                            - "{bucket_name}"
                            - "{bucket_name}/*"
                          Condition:
                            Bool:
                                SecureTransport: "false"

    """
    schema = type_schema("https-request-only")

    required_template = {
            "Effect": "Deny",
            "Principal": {"ID": ["*"]},
            "Action": ["*"],
            "Condition": {"Bool": {"SecureTransport": ["false"]}}
        }

    resource_list_template = ["{bucket_name}", "{bucket_name}/*"]

    def process(self, buckets, event=None):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = list(filter(None, list(results)))
            return results

    def process_bucket(self, bucket):
        self.get_bucket_policy(bucket)

        is_dany_http = self.is_http_deny_enhanced(bucket)

        if not is_dany_http:
            return bucket

        return None

    def is_http_deny_enhanced(self, bucket):
        resource_list = [item.format(bucket_name=bucket['name'])
                         for item in self.resource_list_template]

        policy = bucket.get('Policy') or '{}'
        policy = json.loads(policy)
        bucket_statements = policy.setdefault('Statement', [])

        for s in bucket_statements:
            base_match = all(
                s.get(key) == value
                for key, value in self.required_template.items()
            )

            if not base_match:
                continue

            if self.contain_all_elements(list(s.get('Resource', [])), resource_list):
                return True

        return False

    def contain_all_elements(self, arr1, arr2):
        return set(arr2).issubset(set(arr1))

    def get_bucket_policy(self, bucket):
        client = get_obs_client(self.manager.session_factory, bucket)
        resp = client.getBucketPolicy(bucket['name'])

        if resp.status < 300:
            policy = resp.body.policyJSON
            bucket['Policy'] = policy
        else:
            if 'NoSuchBucketPolicy' == resp.errorCode:
                bucket['Policy'] = {}
                return
            raise_exception(resp, 'getBucketPolicy', bucket)
