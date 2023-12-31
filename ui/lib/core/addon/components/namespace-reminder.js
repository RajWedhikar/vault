/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import { not } from '@ember/object/computed';
import Component from '@ember/component';
import { computed } from '@ember/object';
import layout from '../templates/components/namespace-reminder';

export default Component.extend({
  layout,
  namespace: service(),
  showMessage: not('namespace.inRootNamespace'),
  //public API
  noun: null,
  mode: 'edit',
  modeVerb: computed('mode', function () {
    const mode = this.mode;
    if (!mode) {
      return '';
    }
    return mode.endsWith('e') ? `${mode}d` : `${mode}ed`;
  }),
});
