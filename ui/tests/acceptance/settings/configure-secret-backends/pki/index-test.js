/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { currentRouteName, settled } from '@ember/test-helpers';
import { module, test } from 'qunit';
import { setupApplicationTest } from 'ember-qunit';
import page from 'vault/tests/pages/settings/configure-secret-backends/pki/index';
import authPage from 'vault/tests/pages/auth';
import enablePage from 'vault/tests/pages/settings/mount-secret-backend';

module('Acceptance | settings/configure/secrets/pki', function (hooks) {
  setupApplicationTest(hooks);

  hooks.beforeEach(function () {
    return authPage.login();
  });

  test('it redirects to the cert section', async function (assert) {
    const path = `pki-${new Date().getTime()}`;
    await enablePage.enable('pki', path);
    await settled();
    await page.visit({ backend: path });
    await settled();
    assert.strictEqual(
      currentRouteName(),
      'vault.cluster.settings.configure-secret-backend.section',
      'redirects from the index'
    );
  });
});
