/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@ember/component';
import layout from '../templates/components/layout-loading';

/**
 * @module LayoutLoading
 * `LayoutLoading` displays the `VaultLogoSpinner` component in a centered full-page layout.
 *
 * @example
 * ```js
 * <LayoutLoading />
 * ```
 */

export default Component.extend({
  layout,
  tagName: '',
});
