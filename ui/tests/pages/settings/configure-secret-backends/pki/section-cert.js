/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { create, visitable } from 'ember-cli-page-object';

import ConfigPKICA from 'vault/tests/pages/components/pki/config-pki-ca';
import flashMessages from 'vault/tests/pages/components/flash-message';

export default create({
  visit: visitable('/vault/settings/secrets/configure/:backend/cert'),
  form: ConfigPKICA,
  flash: flashMessages,
});
