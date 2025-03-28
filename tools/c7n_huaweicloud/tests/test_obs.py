# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from huaweicloud_common import BaseTest

import logging
log = logging.getLogger("custodian.huaweicloud.resources.obs")


# class ObsWildcardStatementsTest(BaseTest):
#     def test_obs_query(self):
#         factory = self.replay_flight_data('obs_remove_wildcard_statements')
#         p = self.load_policy({
#              'name': 'list-buckets',
#              'resource': 'huaweicloud.obs'},
#             session_factory=factory)
#         resources = p.run()
#         self.assertEqual(len(resources), 3)


# class ObsEncryptionBucketTest(BaseTest):
    # def test_filter_not_encryptied_buckets(self):
    #     factory = self.replay_flight_data('obs_encryption_bucket')
    #     p = self.load_policy({
    #          'name': 'filter-bucket-encryption',
    #          'resource': 'huaweicloud.obs',
    #          'filters': [{"type": "bucket-encryption", "state": False}]
    #         },
    #         session_factory=factory)
    #     resources = p.run()
    #     self.assertEqual(len(resources), 1)
    #     self.assertEqual(resources[0]['name'], 'test-buckwt-3az3')

    # def test_filter_not_encryptied_with_kms_crypto_buckets(self):
    #     factory = self.replay_flight_data('obs_encryption_bucket')
    #     p = self.load_policy({
    #          'name': 'filter-bucket-encryption',
    #          'resource': 'huaweicloud.obs',
    #          'filters': [{"type": "bucket-encryption", "state": False, "crypto": "kms"}]
    #         },
    #         session_factory=factory)
    #     resources = p.run()
    #     p.
    #     self.assertEqual(len(resources), 2)
    #     self.assertEqual(resources[0]['name'], 'test-buckwt-3az1')
    #     self.assertEqual(resources[0]['c7n:BucketEncryptionCrypto'], 'AES256')
    #     self.assertEqual(resources[1]['name'], 'test-buckwt-3az3')
    #     self.assertEqual(resources[1]['c7n:BucketEncryptionCrypto'], None)

    # def test_filter_encryptied_with_kms_crypto_buckets(self):
    #     factory = self.replay_flight_data('obs_encryption_bucket')
    #     p = self.load_policy({
    #          'name': 'filter-bucket-encryption',
    #          'resource': 'huaweicloud.obs',
    #          'filters': [{"type": "bucket-encryption", "state": True, "crypto": "kms"}]
    #         },
    #         session_factory=factory)
    #     resources = p.run()
    #     self.assertEqual(len(resources), 1)
    #     self.assertEqual(resources[0]['name'], 'test-buckwt-3az2')

    # def test_set_bucket_encryption(self):
    #     factory = self.replay_flight_data('obs_encryption_bucket')
    #     p = self.load_policy({
    #          'name': 'filter-bucket-encryption',
    #          'resource': 'huaweicloud.obs',
    #          'filters': [{"type": "bucket-encryption", "state": False}],
    #          'actions': [{"type": "set-bucket-encryption", "encryption": {"crypto": "AES256"}}]
    #         },
    #         session_factory=factory)
    #     resources = p.run()
    #     self.assertEqual(len(resources), 1)
    #     self.assertEqual(resources[0]['name'], 'test-buckwt-3az3')


# class ObsGlobalGrantsTest(BaseTest):
#     def test_list_bucket_resource(self):
#         factory = self.replay_flight_data('obs_global_grants')
#         p = self.load_policy({
#              'name': 'list-buckets',
#              'resource': 'huaweicloud.obs'},
#             session_factory=factory)
#         resources = p.run()
#         self.assertEqual(len(resources), 3)

#     def test_filter_global_read_write_buckets_not_include_website_bucket(self):
        # factory = self.replay_flight_data('obs_global_grants')
        # p = self.load_policy({
        #      'name': 'filter-global-grant-bucket-1',
        #      'resource': 'huaweicloud.obs',
        #      'filters': [{"type": "global-grants", "allow_website": False}]
        #     },
        #     session_factory=factory)
        # resources = p.run()
        # print(resources)
        # self.assertEqual(len(resources), 2)
        # resources = sorted(resources, key=lambda x : x['name'])
        # self.assertEqual(resources[0]['name'], 'test-buckwt-3az1')
        # self.assertEqual(resources[0]['globalPermissions'], ['READ'])
        # self.assertEqual(resources[1]['name'], 'test-buckwt-3az6')
        # self.assertEqual(resources[1]['globalPermissions'], ['READ', 'WRITE'])


# class ObsPublickBlockTest(BaseTest):
#     def test_set_bucket_open_publick_block_true(self):
#         factory = self.replay_flight_data('obs_block_public_access')
#         p = self.load_policy({
#              'name': 'block-publick-access-bucket-1',
#              'resource': 'huaweicloud.obs',
#              'filters': [{"type": "check-public-block", "blockPublicAcls": False}],
#              'actions': [{"type": "set-public-block", "state": True}]
#             },
#             session_factory=factory)
#         resources = p.run()
#         print(resources)
#         self.assertEqual(len(resources), 2)
