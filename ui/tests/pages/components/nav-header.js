/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { text, isPresent } from 'ember-cli-page-object';

export default {
  ele: isPresent('[data-test-navheader]'),
  homeText: text('[data-test-navheader-home]'),
  itemsText: text('[data-test-navheader-items]'),
  mainText: text('[data-test-navheader-main]'),
};
