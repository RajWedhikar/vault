/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  pathForType() {
    return 'namespaces';
  },
  urlForFindAll(modelName, snapshot) {
    if (snapshot.adapterOptions && snapshot.adapterOptions.forUser) {
      return `/${this.urlPrefix()}/internal/ui/namespaces`;
    }
    return `/${this.urlPrefix()}/namespaces?list=true`;
  },

  urlForCreateRecord(modelName, snapshot) {
    const id = snapshot.attr('path');
    return this.buildURL(modelName, id);
  },

  createRecord(store, type, snapshot) {
    const id = snapshot.attr('path');
    return this._super(...arguments).then(() => {
      return { id };
    });
  },

  findAll(store, type, sinceToken, snapshot) {
    if (snapshot.adapterOptions && typeof snapshot.adapterOptions.namespace !== 'undefined') {
      return this.ajax(this.urlForFindAll('namespace', snapshot), 'GET', {
        namespace: snapshot.adapterOptions.namespace,
      });
    }
    return this._super(...arguments);
  },
  query() {
    return this.ajax(`/${this.urlPrefix()}/namespaces?list=true`);
  },
});
